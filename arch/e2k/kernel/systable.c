/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/syscalls.h>
#include <linux/compat.h>

#include <asm/syscalls.h>
#include <asm/trap_table.h>

#define	SYSTEM_CALL_TBL_ENTRY(sysname)	((system_call_func) (void *) sysname)

#ifdef CONFIG_PROTECTED_MODE
#define	PROT_SYSCALL_TBL_ENTRY(sysname)	((protected_system_call_func) (void *) sysname)
#else
#define	PROT_SYSCALL_TBL_ENTRY(sysname)	((protected_system_call_func) (void *) sys_ni_syscall)
#endif

#ifdef CONFIG_COMPAT
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		((system_call_func) (void *) compat_##sysname)
#else
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		((system_call_func) (void *) sys_ni_syscall)
#endif


static asmlinkage long sys_deprecated(void)
{
	pr_info_ratelimited("System call #%d/%s is obsolete\n",
			    current_pt_regs()->sys_num,
			    SYSCALL_NAME_ON_ID(current_pt_regs()->sys_num));
	return -ENOSYS;
}

/*
 * Real map of system calls.
 */

const system_call_func sys_call_table[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_restart_syscall),	/* 0 */
	SYSTEM_CALL_TBL_ENTRY(sys_exit),
	SYSTEM_CALL_TBL_ENTRY(sys_fork),
	SYSTEM_CALL_TBL_ENTRY(sys_read),
	SYSTEM_CALL_TBL_ENTRY(sys_write),
	SYSTEM_CALL_TBL_ENTRY(sys_open),	/* 5 */
	SYSTEM_CALL_TBL_ENTRY(sys_close),
	SYSTEM_CALL_TBL_ENTRY(sys_waitpid),
	SYSTEM_CALL_TBL_ENTRY(sys_creat),
	SYSTEM_CALL_TBL_ENTRY(sys_link),
	SYSTEM_CALL_TBL_ENTRY(sys_unlink),	/* 10 */
	SYSTEM_CALL_TBL_ENTRY(sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_break */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat */
	SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime),	/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stty */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_gtty */
	SYSTEM_CALL_TBL_ENTRY(sys_access),
	SYSTEM_CALL_TBL_ENTRY(sys_nice),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old sys_ftime */
	SYSTEM_CALL_TBL_ENTRY(sys_sync),
	SYSTEM_CALL_TBL_ENTRY(sys_kill),
	SYSTEM_CALL_TBL_ENTRY(sys_rename),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdir),
	SYSTEM_CALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	SYSTEM_CALL_TBL_ENTRY(sys_dup),
	SYSTEM_CALL_TBL_ENTRY(sys_pipe),
	SYSTEM_CALL_TBL_ENTRY(sys_times),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_prof */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_signal, have to be */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lock */
	SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	/* 55 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mpx */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_ulimit */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_oldolduname */
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigaction, use   */
						/* sys_rt_sigaction instead */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigsuspend */
	SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_old_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_select */
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat */
	SYSTEM_CALL_TBL_ENTRY(sys_readlink),	/* 85 */
	SYSTEM_CALL_TBL_ENTRY(sys_uselib),
	SYSTEM_CALL_TBL_ENTRY(sys_swapon),
	SYSTEM_CALL_TBL_ENTRY(sys_reboot),
	SYSTEM_CALL_TBL_ENTRY(sys_old_readdir),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap),	/* 90 */
	SYSTEM_CALL_TBL_ENTRY(sys_munmap),
	SYSTEM_CALL_TBL_ENTRY(sys_truncate),
	SYSTEM_CALL_TBL_ENTRY(sys_ftruncate),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmod),
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),	/* 95 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_setpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_profil */
	SYSTEM_CALL_TBL_ENTRY(sys_statfs),
	SYSTEM_CALL_TBL_ENTRY(sys_fstatfs),	/* 100 */
	SYSTEM_CALL_TBL_ENTRY(sys_ioperm),
	SYSTEM_CALL_TBL_ENTRY(sys_socketcall),
	SYSTEM_CALL_TBL_ENTRY(sys_syslog),
	SYSTEM_CALL_TBL_ENTRY(sys_setitimer),
	SYSTEM_CALL_TBL_ENTRY(sys_getitimer),	/* 105 */
	SYSTEM_CALL_TBL_ENTRY(sys_newstat),	/* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newlstat),	/* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newfstat),	/* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_uname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110, old sys_iopl */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_idle */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86old */
	SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_sigreturn),
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_modify_ldt */
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_create_module */
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 130, old sys_get_kernel_syms */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_llseek),	/* 140 */
	SYSTEM_CALL_TBL_ENTRY(sys_getdents),
	SYSTEM_CALL_TBL_ENTRY(sys_select),
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	SYSTEM_CALL_TBL_ENTRY(sys_readv),	/* 145 */
	SYSTEM_CALL_TBL_ENTRY(sys_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sysctl */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),		/* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),	/* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_query_module */
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_nfsservctl */
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_prctl),
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),	/* sys_rt_sigreturn() */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigaction),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigtimedwait),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigsuspend),
	SYSTEM_CALL_TBL_ENTRY(sys_pread64),	/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_getpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_putpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_truncate64 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_ftruncate64 */
						/* 
						 * sys_truncate64 & sys_ftruncate64 used
						 * if BITS_PER_LONG == 32.
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195, in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_lstat64),     /* in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_fstat64),     /* in libc used in ptr32 mode */

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),

	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_send_signal),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_open),

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 210 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),	/* 215 */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),

	SYSTEM_CALL_TBL_ENTRY(sys_pivot_root),
	SYSTEM_CALL_TBL_ENTRY(sys_mincore),
	SYSTEM_CALL_TBL_ENTRY(sys_madvise),
	SYSTEM_CALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	/*
						 * sys_fcntl used if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_core */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_newfstatat),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225, old sys_emergency */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_longjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2),/* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_soft_debug */
	SYSTEM_CALL_TBL_ENTRY(sys_setxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_getxattr),	/* 235 */
	SYSTEM_CALL_TBL_ENTRY(sys_lgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_listxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_llistxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_flistxattr),	/* 240 */
	SYSTEM_CALL_TBL_ENTRY(sys_removexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_gettid),
	SYSTEM_CALL_TBL_ENTRY(sys_readahead),	/* 245 */
	SYSTEM_CALL_TBL_ENTRY(sys_tkill),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
#if defined CONFIG_FUTEX
	SYSTEM_CALL_TBL_ENTRY(sys_futex),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setaffinity),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	SYSTEM_CALL_TBL_ENTRY(sys_pipe2),
	SYSTEM_CALL_TBL_ENTRY(sys_set_backtrace),
	SYSTEM_CALL_TBL_ENTRY(sys_get_backtrace),
	SYSTEM_CALL_TBL_ENTRY(sys_access_hw_stacks),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_enter),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_register),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary),		/* 260 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */	
	SYSTEM_CALL_TBL_ENTRY(sys_timer_create),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_settime),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_gettime),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_getoverrun),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_delete),	/* 265 */
	SYSTEM_CALL_TBL_ENTRY(sys_clock_settime),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_gettime),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_getres),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_nanosleep),
	SYSTEM_CALL_TBL_ENTRY(sys_msgget),		/* 270 */
	SYSTEM_CALL_TBL_ENTRY(sys_msgctl),
	SYSTEM_CALL_TBL_ENTRY(sys_msgrcv),
	SYSTEM_CALL_TBL_ENTRY(sys_msgsnd),
	SYSTEM_CALL_TBL_ENTRY(sys_semget),
	SYSTEM_CALL_TBL_ENTRY(sys_semctl),		/* 275 */
	SYSTEM_CALL_TBL_ENTRY(sys_semtimedop),
	SYSTEM_CALL_TBL_ENTRY(sys_semop),
	SYSTEM_CALL_TBL_ENTRY(sys_shmget),
	SYSTEM_CALL_TBL_ENTRY(sys_shmctl),
	SYSTEM_CALL_TBL_ENTRY(sys_shmat),		/* 280 */
	SYSTEM_CALL_TBL_ENTRY(sys_shmdt),
	SYSTEM_CALL_TBL_ENTRY(sys_open_tree),
	SYSTEM_CALL_TBL_ENTRY(sys_move_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_rseq),
	SYSTEM_CALL_TBL_ENTRY(sys_io_pgetevents),	/* 285 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept4),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setattr),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getattr),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
	SYSTEM_CALL_TBL_ENTRY(sys_io_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),	/* 295 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
	SYSTEM_CALL_TBL_ENTRY(sys_fadvise64),  
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group), /* 300 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait), 
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages),	/* 305 */
	SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes), 
	SYSTEM_CALL_TBL_ENTRY(sys_fadvise64_64),	/* 310 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* old sys_vserver */
	SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_open),		/* 315 */
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr),	/* 320 */
	SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
	SYSTEM_CALL_TBL_ENTRY(sys_keyctl),	/* 325 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mcst_rt */
	SYSTEM_CALL_TBL_ENTRY(sys_getcpu),
	SYSTEM_CALL_TBL_ENTRY(sys_move_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_splice),
	SYSTEM_CALL_TBL_ENTRY(sys_vmsplice),	/* 330 */
	SYSTEM_CALL_TBL_ENTRY(sys_tee),
	SYSTEM_CALL_TBL_ENTRY(sys_migrate_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_utimensat),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_tgsigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_openat),	/* 335 */
	SYSTEM_CALL_TBL_ENTRY(sys_mkdirat),
	SYSTEM_CALL_TBL_ENTRY(sys_mknodat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchownat),
	SYSTEM_CALL_TBL_ENTRY(sys_unlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_renameat),	/* 340 */
	SYSTEM_CALL_TBL_ENTRY(sys_linkat),
	SYSTEM_CALL_TBL_ENTRY(sys_symlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_readlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmodat),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat),	/* 345 */
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_pwait),
	SYSTEM_CALL_TBL_ENTRY(sys_signalfd4),
	SYSTEM_CALL_TBL_ENTRY(sys_eventfd2),
	SYSTEM_CALL_TBL_ENTRY(sys_recvmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
#ifdef CONFIG_TIMERFD
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_settime),
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_gettime),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_preadv),
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev),	/* 355 */
	SYSTEM_CALL_TBL_ENTRY(sys_fallocate),
	SYSTEM_CALL_TBL_ENTRY(sys_sync_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),	/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat),
	SYSTEM_CALL_TBL_ENTRY(sys_perf_event_open),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	SYSTEM_CALL_TBL_ENTRY(sys_get_robust_list),	/* 365 */
	SYSTEM_CALL_TBL_ENTRY(sys_set_robust_list),
	SYSTEM_CALL_TBL_ENTRY(sys_pselect6),
	SYSTEM_CALL_TBL_ENTRY(sys_ppoll),
	SYSTEM_CALL_TBL_ENTRY(sys_setcontext),
	SYSTEM_CALL_TBL_ENTRY(sys_makecontext),		/* 370 */
	SYSTEM_CALL_TBL_ENTRY(sys_swapcontext),
	SYSTEM_CALL_TBL_ENTRY(sys_freecontext),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_init),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_mark),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_prlimit64),	/* 375 */
	SYSTEM_CALL_TBL_ENTRY(sys_clock_adjtime),
	SYSTEM_CALL_TBL_ENTRY(sys_syncfs),
	SYSTEM_CALL_TBL_ENTRY(sys_sendmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_setns),
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_readv),	/* 380 */
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_kcmp),
	SYSTEM_CALL_TBL_ENTRY(sys_finit_module),

	/* added in linux-4.4 */
	SYSTEM_CALL_TBL_ENTRY(sys_renameat2),
	SYSTEM_CALL_TBL_ENTRY(sys_getrandom),	/* 385 */
	SYSTEM_CALL_TBL_ENTRY(sys_memfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_bpf),
	SYSTEM_CALL_TBL_ENTRY(sys_execveat),
	SYSTEM_CALL_TBL_ENTRY(sys_userfaultfd),
	SYSTEM_CALL_TBL_ENTRY(sys_membarrier),	/* 390 */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock2),

	/* added in linux-4.9 */
	SYSTEM_CALL_TBL_ENTRY(sys_seccomp),
	SYSTEM_CALL_TBL_ENTRY(sys_shutdown),
	SYSTEM_CALL_TBL_ENTRY(sys_copy_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_preadv2),	/* 395 */
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev2),

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	SYSTEM_CALL_TBL_ENTRY(sys_open_by_handle_at),
	SYSTEM_CALL_TBL_ENTRY(sys_statx),

	/* added for compatibility with x86_64 */
	SYSTEM_CALL_TBL_ENTRY(sys_socket),
	SYSTEM_CALL_TBL_ENTRY(sys_connect),
	SYSTEM_CALL_TBL_ENTRY(sys_accept),	/* 405 */
	SYSTEM_CALL_TBL_ENTRY(sys_sendto),
	SYSTEM_CALL_TBL_ENTRY(sys_recvfrom),
	SYSTEM_CALL_TBL_ENTRY(sys_sendmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_recvmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_bind),	/* 410 */
	SYSTEM_CALL_TBL_ENTRY(sys_listen),
	SYSTEM_CALL_TBL_ENTRY(sys_getsockname),
	SYSTEM_CALL_TBL_ENTRY(sys_getpeername),
	SYSTEM_CALL_TBL_ENTRY(sys_socketpair),
	SYSTEM_CALL_TBL_ENTRY(sys_setsockopt),	/* 415 */
	SYSTEM_CALL_TBL_ENTRY(sys_getsockopt),

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_arch_prctl */

	/* protected specific system calls entries */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 420, sys_newuselib */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigaction_ex */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_get_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_free_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* sys_clean_descriptors */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 425, sys_unuselib */

	SYSTEM_CALL_TBL_ENTRY(sys_clone3),
	SYSTEM_CALL_TBL_ENTRY(sys_fsopen),
	SYSTEM_CALL_TBL_ENTRY(sys_fsconfig),
	SYSTEM_CALL_TBL_ENTRY(sys_fsmount),
	SYSTEM_CALL_TBL_ENTRY(sys_fspick),	/* 430 */

	/* added for Linux 5.10 */
	SYSTEM_CALL_TBL_ENTRY(sys_close_range),
	SYSTEM_CALL_TBL_ENTRY(sys_openat2),
	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_getfd),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat2),
	SYSTEM_CALL_TBL_ENTRY(sys_process_madvise),		/* 435 */

	/* added for Linux 5.15 */
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_pwait2),
	SYSTEM_CALL_TBL_ENTRY(sys_mount_setattr),
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl_fd),
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_create_ruleset),
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_add_rule),		/* 440 */
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_restrict_self),
	SYSTEM_CALL_TBL_ENTRY(sys_process_mrelease),

	/* added for Linux 6.1 */
	SYSTEM_CALL_TBL_ENTRY(sys_futex_waitv),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy_home_node),

	/* added for soft secure (unsafe) protected mode */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* unsafe_uint64_to_ptr */

	/* 445 last System call */
};

#ifdef CONFIG_COMPAT
const system_call_func sys_call_table_32[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_restart_syscall),	/* 0 */
	SYSTEM_CALL_TBL_ENTRY(sys_exit),
	SYSTEM_CALL_TBL_ENTRY(sys_fork),
	SYSTEM_CALL_TBL_ENTRY(sys_read),
	SYSTEM_CALL_TBL_ENTRY(sys_write),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_open),	/* 5 */
	SYSTEM_CALL_TBL_ENTRY(sys_close),
	SYSTEM_CALL_TBL_ENTRY(sys_waitpid),
	SYSTEM_CALL_TBL_ENTRY(sys_creat),
	SYSTEM_CALL_TBL_ENTRY(sys_link),
	SYSTEM_CALL_TBL_ENTRY(sys_unlink),	/* 10 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_break */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime32),	/* 25 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime32),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stty */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_gtty */
	SYSTEM_CALL_TBL_ENTRY(sys_access),
	SYSTEM_CALL_TBL_ENTRY(sys_nice),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old sys_ftime */
	SYSTEM_CALL_TBL_ENTRY(sys_sync),
	SYSTEM_CALL_TBL_ENTRY(sys_kill),
	SYSTEM_CALL_TBL_ENTRY(sys_rename),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdir),
	SYSTEM_CALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	SYSTEM_CALL_TBL_ENTRY(sys_dup),
	SYSTEM_CALL_TBL_ENTRY(sys_pipe),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_times),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_prof */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_signal, have to be */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lock */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),/* 55 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mpx */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_ulimit */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigaction, use   */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),	/* sys_rt_sigaction instead */
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigsuspend */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_select */
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat */
	SYSTEM_CALL_TBL_ENTRY(sys_readlink),	/* 85 */
	SYSTEM_CALL_TBL_ENTRY(sys_uselib),
	SYSTEM_CALL_TBL_ENTRY(sys_swapon),
	SYSTEM_CALL_TBL_ENTRY(sys_reboot),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_old_readdir),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap),	/* 90 */
	SYSTEM_CALL_TBL_ENTRY(sys_munmap),
	SYSTEM_CALL_TBL_ENTRY(sys_truncate),
	SYSTEM_CALL_TBL_ENTRY(sys_ftruncate),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmod),
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),	/* 95 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_setpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_profil */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs),	/* 100 */
	SYSTEM_CALL_TBL_ENTRY(sys_ioperm),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_socketcall),
	SYSTEM_CALL_TBL_ENTRY(sys_syslog),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_setitimer),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getitimer),	/* 105 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_newstat),     
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_newlstat),   
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_newfstat),   
	SYSTEM_CALL_TBL_ENTRY(sys_uname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110, old sys_iopl */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_idle */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_sigreturn),
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_modify_ldt */
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_create_module */
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 130, old sys_get_kernel_syms */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_llseek),	/* 140 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_select),
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	SYSTEM_CALL_TBL_ENTRY(sys_readv),	/* 145 */
	SYSTEM_CALL_TBL_ENTRY(sys_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sysctl */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),		/* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),	/* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_query_module */
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_nfsservctl */
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_prctl),
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),	/* sys_rt_sigreturn() */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigaction),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigtimedwait_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigsuspend),
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),	/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_getpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_putpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),
	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64), 
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195, in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_lstat64),     /* in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_fstat64),     /* in libc used in ptr32 mode */

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),

	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_send_signal),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_open),

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 210 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),	/* 215 */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),

	SYSTEM_CALL_TBL_ENTRY(sys_pivot_root),
	SYSTEM_CALL_TBL_ENTRY(sys_mincore),
	SYSTEM_CALL_TBL_ENTRY(sys_madvise),
	SYSTEM_CALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl64),	/*
							 * sys_fcntl64 used if
							 * if BITS_PER_LONG == 32
							 * for some other archs
							 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225, old sys_emergency */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_longjmp*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2),/* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_soft_debug */
	SYSTEM_CALL_TBL_ENTRY(sys_setxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_getxattr),	/* 235 */
	SYSTEM_CALL_TBL_ENTRY(sys_lgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_listxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_llistxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_flistxattr),	/* 240 */
	SYSTEM_CALL_TBL_ENTRY(sys_removexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_gettid),
	SYSTEM_CALL_TBL_ENTRY(sys32_readahead),	/* 245 */
	SYSTEM_CALL_TBL_ENTRY(sys_tkill),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
#if defined CONFIG_FUTEX
	SYSTEM_CALL_TBL_ENTRY(sys_futex_time32),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_setaffinity),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	SYSTEM_CALL_TBL_ENTRY(sys_pipe2),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_backtrace),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_backtrace),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_access_hw_stacks),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_enter),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_register),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary),	/* 260 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */	
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_create),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_settime32),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_gettime32),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_getoverrun),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_delete),	/* 265 */
	SYSTEM_CALL_TBL_ENTRY(sys_clock_settime32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_gettime32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_getres_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_nanosleep_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_msgget),	/* 270 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_msgctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_msgrcv),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_msgsnd),
	SYSTEM_CALL_TBL_ENTRY(sys_semget),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_semctl),	/* 275 */
	SYSTEM_CALL_TBL_ENTRY(sys_semtimedop_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_semop),
	SYSTEM_CALL_TBL_ENTRY(sys_shmget),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_shmctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_shmat),	/* 280 */
	SYSTEM_CALL_TBL_ENTRY(sys_shmdt),
	SYSTEM_CALL_TBL_ENTRY(sys_open_tree),
	SYSTEM_CALL_TBL_ENTRY(sys_move_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_rseq),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_pgetevents), /* 285 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept4),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setattr),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getattr),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),  /* 295 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64),  
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group), /* 300 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait), 
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages),	/* 305 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes_time32),
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64),	/* 310 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* old sys_vserver */
	SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),	/* 315 */
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr),/* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_keyctl),	/* 325 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mcst_rt */
	SYSTEM_CALL_TBL_ENTRY(sys_getcpu),
	SYSTEM_CALL_TBL_ENTRY(sys_move_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_splice),
	SYSTEM_CALL_TBL_ENTRY(sys_vmsplice),	/* 330 */
	SYSTEM_CALL_TBL_ENTRY(sys_tee),
	SYSTEM_CALL_TBL_ENTRY(sys_migrate_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_utimensat_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_tgsigqueueinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_openat),	/* 335 */
	SYSTEM_CALL_TBL_ENTRY(sys_mkdirat),
	SYSTEM_CALL_TBL_ENTRY(sys_mknodat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchownat),
	SYSTEM_CALL_TBL_ENTRY(sys_unlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_renameat),	/* 340 */
	SYSTEM_CALL_TBL_ENTRY(sys_linkat),
	SYSTEM_CALL_TBL_ENTRY(sys_symlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_readlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmodat),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat),	/* 345 */
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_pwait),
#ifdef CONFIG_SIGNALFD
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_signalfd4),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_eventfd2),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvmmsg_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
#ifdef CONFIG_TIMERFD
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_settime32),
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_gettime32),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_preadv),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pwritev),	/* 355 */
	SYSTEM_CALL_TBL_ENTRY(sys32_fallocate),
	SYSTEM_CALL_TBL_ENTRY(sys32_sync_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),	/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_perf_event_open),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_robust_list),	/* 365 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_robust_list),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pselect6_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ppoll_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_setcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_makecontext),	/* 370 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_swapcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_freecontext),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_init),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fanotify_mark),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_prlimit64),	/* 375 */
	SYSTEM_CALL_TBL_ENTRY(sys_clock_adjtime32),
	SYSTEM_CALL_TBL_ENTRY(sys_syncfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_setns),
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_readv),	/* 380 */
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_kcmp),
	SYSTEM_CALL_TBL_ENTRY(sys_finit_module),

	/* added in linux-4.4 */
	SYSTEM_CALL_TBL_ENTRY(sys_renameat2),
	SYSTEM_CALL_TBL_ENTRY(sys_getrandom),		/* 385 */
	SYSTEM_CALL_TBL_ENTRY(sys_memfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_bpf),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_execveat),
	SYSTEM_CALL_TBL_ENTRY(sys_userfaultfd),
	SYSTEM_CALL_TBL_ENTRY(sys_membarrier),		/* 390 */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock2),

	/* added in linux-4.9 */
	SYSTEM_CALL_TBL_ENTRY(sys_seccomp),
	SYSTEM_CALL_TBL_ENTRY(sys_shutdown),
	SYSTEM_CALL_TBL_ENTRY(sys_copy_file_range),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_preadv2),	/* 395 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pwritev2),

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_open_by_handle_at),
	SYSTEM_CALL_TBL_ENTRY(sys_statx),

	/* added for compatibility with x86_64 */
	SYSTEM_CALL_TBL_ENTRY(sys_socket),
	SYSTEM_CALL_TBL_ENTRY(sys_connect),
	SYSTEM_CALL_TBL_ENTRY(sys_accept),		/* 405 */
	SYSTEM_CALL_TBL_ENTRY(sys_sendto),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvfrom),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendmsg),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_bind),		/* 410 */
	SYSTEM_CALL_TBL_ENTRY(sys_listen),
	SYSTEM_CALL_TBL_ENTRY(sys_getsockname),
	SYSTEM_CALL_TBL_ENTRY(sys_getpeername),
	SYSTEM_CALL_TBL_ENTRY(sys_socketpair),
	SYSTEM_CALL_TBL_ENTRY(sys_setsockopt),		/* 415 */
	SYSTEM_CALL_TBL_ENTRY(sys_getsockopt),

	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvmmsg_time64),	/* 417 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 418 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_arch_prctl */

	/* protected specific system calls entries */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 420, sys_newuselib */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigaction_ex */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_get_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_free_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* sys_clean_descriptors */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 425, sys_unuselib */

	SYSTEM_CALL_TBL_ENTRY(sys_clone3),
	SYSTEM_CALL_TBL_ENTRY(sys_fsopen),
	SYSTEM_CALL_TBL_ENTRY(sys_fsconfig),
	SYSTEM_CALL_TBL_ENTRY(sys_fsmount),
	SYSTEM_CALL_TBL_ENTRY(sys_fspick),	/* 430 */

	/* added for Linux 5.10 */
	SYSTEM_CALL_TBL_ENTRY(sys_close_range),
	SYSTEM_CALL_TBL_ENTRY(sys_openat2),
	SYSTEM_CALL_TBL_ENTRY(sys_pidfd_getfd),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat2),
	SYSTEM_CALL_TBL_ENTRY(sys_process_madvise),	/* 435 */

	/* added for Linux 5.15 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_epoll_pwait2),
	SYSTEM_CALL_TBL_ENTRY(sys_mount_setattr),
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl_fd),
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_create_ruleset),
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_add_rule),		/* 440 */
	SYSTEM_CALL_TBL_ENTRY(sys_landlock_restrict_self),
	SYSTEM_CALL_TBL_ENTRY(sys_process_mrelease),

	/* added for Linux 6.1 */
	SYSTEM_CALL_TBL_ENTRY(sys_futex_waitv),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy_home_node),

	/* added for soft secure (unsafe) protected mode */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* unsafe_uint64_to_ptr */

	/* 445 last System call */
};
#endif /* CONFIG_COMPAT */

#ifdef CONFIG_PROTECTED_MODE
/*
 * System call handlers for protected mode entry #8:
 */
const protected_system_call_func sys_call_table_entry8[NR_syscalls] = {
	PROT_SYSCALL_TBL_ENTRY(sys_restart_syscall),	/* 0 */
	PROT_SYSCALL_TBL_ENTRY(sys_exit),
	PROT_SYSCALL_TBL_ENTRY(sys_fork),
	PROT_SYSCALL_TBL_ENTRY(sys_read),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_write),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_open),	/* 5 */
	PROT_SYSCALL_TBL_ENTRY(sys_close),
	PROT_SYSCALL_TBL_ENTRY(sys_waitpid),
	PROT_SYSCALL_TBL_ENTRY(sys_creat),
	PROT_SYSCALL_TBL_ENTRY(sys_link),
	PROT_SYSCALL_TBL_ENTRY(sys_unlink),	/* 10 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_execve),
	PROT_SYSCALL_TBL_ENTRY(sys_chdir),
	PROT_SYSCALL_TBL_ENTRY(sys_time),
	PROT_SYSCALL_TBL_ENTRY(sys_mknod),
	PROT_SYSCALL_TBL_ENTRY(sys_chmod),	/* 15 */
	PROT_SYSCALL_TBL_ENTRY(sys_lchown),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_break */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat */
	PROT_SYSCALL_TBL_ENTRY(sys_lseek),
	PROT_SYSCALL_TBL_ENTRY(sys_getpid),	/* 20 */
	PROT_SYSCALL_TBL_ENTRY(sys_mount),
	PROT_SYSCALL_TBL_ENTRY(sys_oldumount),
	PROT_SYSCALL_TBL_ENTRY(sys_setuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getuid),
	PROT_SYSCALL_TBL_ENTRY(sys_stime),	/* 25 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_ptrace),
	PROT_SYSCALL_TBL_ENTRY(sys_alarm),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat */
	PROT_SYSCALL_TBL_ENTRY(sys_pause),
	PROT_SYSCALL_TBL_ENTRY(sys_utime),	/* 30 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stty */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_gtty */
	PROT_SYSCALL_TBL_ENTRY(sys_access),
	PROT_SYSCALL_TBL_ENTRY(sys_nice),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old sys_ftime */
	PROT_SYSCALL_TBL_ENTRY(sys_sync),
	PROT_SYSCALL_TBL_ENTRY(sys_kill),
	PROT_SYSCALL_TBL_ENTRY(sys_rename),
	PROT_SYSCALL_TBL_ENTRY(sys_mkdir),
	PROT_SYSCALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	PROT_SYSCALL_TBL_ENTRY(sys_dup),
	PROT_SYSCALL_TBL_ENTRY(sys_pipe),
	PROT_SYSCALL_TBL_ENTRY(sys_times),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_prof */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_brk), /* 45 */
	PROT_SYSCALL_TBL_ENTRY(sys_setgid),
	PROT_SYSCALL_TBL_ENTRY(sys_getgid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_signal(), have to be	*/
						/* emulated by rt_sigaction()	*/
						/* on user level (GLIBC)	*/
	PROT_SYSCALL_TBL_ENTRY(sys_geteuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getegid),	/* 50 */
	PROT_SYSCALL_TBL_ENTRY(sys_acct),
	PROT_SYSCALL_TBL_ENTRY(sys_umount),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lock */
	PROT_SYSCALL_TBL_ENTRY(sys_protected_ioctl),
	PROT_SYSCALL_TBL_ENTRY(sys_fcntl),	/* 55 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mpx */
	PROT_SYSCALL_TBL_ENTRY(sys_setpgid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_ulimit */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_oldolduname */
	PROT_SYSCALL_TBL_ENTRY(sys_umask),	/* 60 */
	PROT_SYSCALL_TBL_ENTRY(sys_chroot),
	PROT_SYSCALL_TBL_ENTRY(sys_ustat),
	PROT_SYSCALL_TBL_ENTRY(sys_dup2),
	PROT_SYSCALL_TBL_ENTRY(sys_getppid),
	PROT_SYSCALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	PROT_SYSCALL_TBL_ENTRY(sys_setsid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigaction, use     */
						/* sys_rt_sigaction() instead */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_sgetmask obsoleted */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_ssetmask obsoleted */
	PROT_SYSCALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	PROT_SYSCALL_TBL_ENTRY(sys_setregid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigsuspend */
	PROT_SYSCALL_TBL_ENTRY(sys_sigpending),
	PROT_SYSCALL_TBL_ENTRY(sys_sethostname),
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_old_getrlimit),
	PROT_SYSCALL_TBL_ENTRY(sys_getrusage),
	PROT_SYSCALL_TBL_ENTRY(sys_gettimeofday),
	PROT_SYSCALL_TBL_ENTRY(sys_settimeofday),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_getgroups),	/* 80 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_setgroups),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_select),
	PROT_SYSCALL_TBL_ENTRY(sys_symlink),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat */
	PROT_SYSCALL_TBL_ENTRY(sys_readlink),	/* 85 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_uselib),
	PROT_SYSCALL_TBL_ENTRY(sys_swapon),
	PROT_SYSCALL_TBL_ENTRY(sys_reboot),
	PROT_SYSCALL_TBL_ENTRY(sys_old_readdir),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mmap),	/* 90 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_munmap),
	PROT_SYSCALL_TBL_ENTRY(sys_truncate),
	PROT_SYSCALL_TBL_ENTRY(sys_ftruncate),
	PROT_SYSCALL_TBL_ENTRY(sys_fchmod),
	PROT_SYSCALL_TBL_ENTRY(sys_fchown),	/* 95 */
	PROT_SYSCALL_TBL_ENTRY(sys_getpriority),
	PROT_SYSCALL_TBL_ENTRY(sys_setpriority),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_profil */
	PROT_SYSCALL_TBL_ENTRY(sys_statfs),
	PROT_SYSCALL_TBL_ENTRY(sys_fstatfs),	/* 100 */
	PROT_SYSCALL_TBL_ENTRY(sys_ioperm),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_socketcall),
	PROT_SYSCALL_TBL_ENTRY(sys_syslog),
	PROT_SYSCALL_TBL_ENTRY(sys_setitimer),
	PROT_SYSCALL_TBL_ENTRY(sys_getitimer),	/* 105 */

	PROT_SYSCALL_TBL_ENTRY(sys_newstat),	/* in libc used in ptr64 mode */
	PROT_SYSCALL_TBL_ENTRY(sys_newlstat),	/* in libc used in ptr64 mode */
	PROT_SYSCALL_TBL_ENTRY(sys_newfstat),	/* in libc used in ptr64 mode */

	PROT_SYSCALL_TBL_ENTRY(sys_uname),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 110, old sys_iopl */
	PROT_SYSCALL_TBL_ENTRY(sys_vhangup),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_idle */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86old */
	PROT_SYSCALL_TBL_ENTRY(sys_wait4),
	PROT_SYSCALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	PROT_SYSCALL_TBL_ENTRY(sys_sysinfo),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_ipc),
	PROT_SYSCALL_TBL_ENTRY(sys_fsync),
	PROT_SYSCALL_TBL_ENTRY(sys_sigreturn),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_clone),	/* 120 */
	PROT_SYSCALL_TBL_ENTRY(sys_setdomainname),
	PROT_SYSCALL_TBL_ENTRY(sys_newuname),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_adjtimex),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mprotect),	/* 125 */
	PROT_SYSCALL_TBL_ENTRY(sys_sigprocmask),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_create_module */
	PROT_SYSCALL_TBL_ENTRY(sys_init_module),
	PROT_SYSCALL_TBL_ENTRY(sys_delete_module),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	PROT_SYSCALL_TBL_ENTRY(sys_quotactl),
	PROT_SYSCALL_TBL_ENTRY(sys_getpgid),
	PROT_SYSCALL_TBL_ENTRY(sys_fchdir),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	PROT_SYSCALL_TBL_ENTRY(sys_personality),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_afs_syscall */
	PROT_SYSCALL_TBL_ENTRY(sys_setfsuid),
	PROT_SYSCALL_TBL_ENTRY(sys_setfsgid),
	PROT_SYSCALL_TBL_ENTRY(sys_llseek),	/* 140 */
	PROT_SYSCALL_TBL_ENTRY(sys_getdents),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_select),
	PROT_SYSCALL_TBL_ENTRY(sys_flock),
	PROT_SYSCALL_TBL_ENTRY(sys_msync),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_readv),		/* 145 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_writev),
	PROT_SYSCALL_TBL_ENTRY(sys_getsid),
	PROT_SYSCALL_TBL_ENTRY(sys_fdatasync),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),			/* old sys_sysctl */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mlock),			/* 150 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_munlock),
	PROT_SYSCALL_TBL_ENTRY(sys_mlockall),
	PROT_SYSCALL_TBL_ENTRY(sys_munlockall),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setparam),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getparam),		/* 155 */
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setscheduler),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getscheduler),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_yield),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_get_priority_max),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_get_priority_min),	/* 160 */
	PROT_SYSCALL_TBL_ENTRY(sys_sched_rr_get_interval),
	PROT_SYSCALL_TBL_ENTRY(sys_nanosleep),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mremap),
	PROT_SYSCALL_TBL_ENTRY(sys_setresuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_query_module */
	PROT_SYSCALL_TBL_ENTRY(sys_poll),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_nfsservctl */
	PROT_SYSCALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	PROT_SYSCALL_TBL_ENTRY(sys_getresgid),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_prctl),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigreturn	*/
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigaction),
	PROT_SYSCALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	PROT_SYSCALL_TBL_ENTRY(sys_rt_sigpending),
	PROT_SYSCALL_TBL_ENTRY(prot_rt_sigtimedwait),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigqueueinfo),
	PROT_SYSCALL_TBL_ENTRY(sys_rt_sigsuspend),
	PROT_SYSCALL_TBL_ENTRY(sys_pread64),		/* 180 */
	PROT_SYSCALL_TBL_ENTRY(sys_pwrite64),
	PROT_SYSCALL_TBL_ENTRY(sys_chown),
	PROT_SYSCALL_TBL_ENTRY(sys_getcwd),
	PROT_SYSCALL_TBL_ENTRY(sys_capget),
	PROT_SYSCALL_TBL_ENTRY(sys_capset),	/* 185 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_sigaltstack),
	PROT_SYSCALL_TBL_ENTRY(sys_sendfile64),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_getpmsg */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_putpmsg */
	PROT_SYSCALL_TBL_ENTRY(sys_vfork),	/* 190 */
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_getrlimit),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mmap2),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall), /* sys_truncate64	*/
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_ftruncate64	*/
						/*
						 * sys_truncate64 & sys_ftruncate64 used
						 * if BITS_PER_LONG == 32.
						 */
	PROT_SYSCALL_TBL_ENTRY(sys_stat64), /* 195, in libc used in ptr32 mode */
	PROT_SYSCALL_TBL_ENTRY(sys_lstat64),
	PROT_SYSCALL_TBL_ENTRY(sys_fstat64),

	/*
	 * They are used for back compatibility
	 */
	PROT_SYSCALL_TBL_ENTRY(sys_lchown),
	PROT_SYSCALL_TBL_ENTRY(sys_getuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getgid),	/* 200 */
	PROT_SYSCALL_TBL_ENTRY(sys_geteuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getegid),
	PROT_SYSCALL_TBL_ENTRY(sys_setreuid),
	PROT_SYSCALL_TBL_ENTRY(sys_setregid),

	PROT_SYSCALL_TBL_ENTRY(sys_pidfd_send_signal), /* 205 */
	PROT_SYSCALL_TBL_ENTRY(sys_pidfd_open),

	/*
	 * They are used for back compatibility
	 */
	PROT_SYSCALL_TBL_ENTRY(sys_fchown),
	PROT_SYSCALL_TBL_ENTRY(sys_setresuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getresuid),
	PROT_SYSCALL_TBL_ENTRY(sys_setresgid),	/* 210 */
	PROT_SYSCALL_TBL_ENTRY(sys_getresgid),
	PROT_SYSCALL_TBL_ENTRY(sys_chown),
	PROT_SYSCALL_TBL_ENTRY(sys_setuid),
	PROT_SYSCALL_TBL_ENTRY(sys_setgid),
	PROT_SYSCALL_TBL_ENTRY(sys_setfsuid),	/* 215 */
	PROT_SYSCALL_TBL_ENTRY(sys_setfsgid),

	PROT_SYSCALL_TBL_ENTRY(sys_pivot_root),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mincore),
	PROT_SYSCALL_TBL_ENTRY(sys_madvise),
	PROT_SYSCALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	PROT_SYSCALL_TBL_ENTRY(sys_fcntl),	/*
						 * sys_fcntl used if BITS_PER_LONG == 32
						 * for some other archs
						 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_core */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_newfstatat),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 225, old sys_emergency */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_e2k_setjmp */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_e2k_longjmp */
	PROT_SYSCALL_TBL_ENTRY(sys_e2k_syswork),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone_thread */
	PROT_SYSCALL_TBL_ENTRY(sys_e2k_longjmp2),	/* 230 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_soft_debug */
	PROT_SYSCALL_TBL_ENTRY(sys_setxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_lsetxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_fsetxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_getxattr),	/* 235 */
	PROT_SYSCALL_TBL_ENTRY(sys_lgetxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_fgetxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_listxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_llistxattr),
	PROT_SYSCALL_TBL_ENTRY(sys_flistxattr),	/* 240 */
	PROT_SYSCALL_TBL_ENTRY(sys_removexattr),
	PROT_SYSCALL_TBL_ENTRY(sys_lremovexattr),
	PROT_SYSCALL_TBL_ENTRY(sys_fremovexattr),
	PROT_SYSCALL_TBL_ENTRY(sys_gettid),
	PROT_SYSCALL_TBL_ENTRY(sys_readahead),	/* 245 */
	PROT_SYSCALL_TBL_ENTRY(sys_tkill),
	PROT_SYSCALL_TBL_ENTRY(sys_sendfile64),
#if defined CONFIG_FUTEX
	PROT_SYSCALL_TBL_ENTRY(protected_sys_futex),
#else
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
#endif
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setaffinity),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	PROT_SYSCALL_TBL_ENTRY(sys_pipe2),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_set_backtrace),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_get_backtrace),
	PROT_SYSCALL_TBL_ENTRY(sys_access_hw_stacks),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* 255 */
	PROT_SYSCALL_TBL_ENTRY(sys_io_uring_setup),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_io_uring_enter),
	PROT_SYSCALL_TBL_ENTRY(protected_syscall_notyetsupported), /* 258 - sys_io_uring_register */
	PROT_SYSCALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	PROT_SYSCALL_TBL_ENTRY(sys_el_binary),		/* 260 */
#else
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_timer_create),
	PROT_SYSCALL_TBL_ENTRY(sys_timer_settime),
	PROT_SYSCALL_TBL_ENTRY(sys_timer_gettime),
	PROT_SYSCALL_TBL_ENTRY(sys_timer_getoverrun),
	PROT_SYSCALL_TBL_ENTRY(sys_timer_delete),	/* 265 */
	PROT_SYSCALL_TBL_ENTRY(sys_clock_settime),
	PROT_SYSCALL_TBL_ENTRY(sys_clock_gettime),
	PROT_SYSCALL_TBL_ENTRY(sys_clock_getres),
	PROT_SYSCALL_TBL_ENTRY(sys_clock_nanosleep),
	PROT_SYSCALL_TBL_ENTRY(sys_msgget),		/* 270 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_msgctl),
	PROT_SYSCALL_TBL_ENTRY(sys_msgrcv),
	PROT_SYSCALL_TBL_ENTRY(sys_msgsnd),
	PROT_SYSCALL_TBL_ENTRY(sys_semget),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_semctl),	/* 275 */
	PROT_SYSCALL_TBL_ENTRY(sys_semtimedop),
	PROT_SYSCALL_TBL_ENTRY(sys_semop),
	PROT_SYSCALL_TBL_ENTRY(sys_shmget),
	PROT_SYSCALL_TBL_ENTRY(sys_shmctl),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_shmat),	/* 280 */
	PROT_SYSCALL_TBL_ENTRY(sys_shmdt),
	PROT_SYSCALL_TBL_ENTRY(sys_open_tree),
	PROT_SYSCALL_TBL_ENTRY(sys_move_mount),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* 285 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_accept4),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setattr),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getattr),
	PROT_SYSCALL_TBL_ENTRY(sys_ioprio_set),
	PROT_SYSCALL_TBL_ENTRY(sys_ioprio_get),		/* 290 */
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_init),
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_add_watch),
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_rm_watch),
	PROT_SYSCALL_TBL_ENTRY(sys_io_setup),
	PROT_SYSCALL_TBL_ENTRY(sys_io_destroy),		/* 295 */
	PROT_SYSCALL_TBL_ENTRY(sys_io_getevents),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_io_submit),
	PROT_SYSCALL_TBL_ENTRY(sys_io_cancel),
	PROT_SYSCALL_TBL_ENTRY(sys_fadvise64),
	PROT_SYSCALL_TBL_ENTRY(sys_exit_group),		/* 300 */
	PROT_SYSCALL_TBL_ENTRY(sys_lookup_dcookie),
	PROT_SYSCALL_TBL_ENTRY(sys_epoll_create),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_ctl),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_wait),
	PROT_SYSCALL_TBL_ENTRY(sys_remap_file_pages),	/* 305 */
	PROT_SYSCALL_TBL_ENTRY(sys_statfs64),
	PROT_SYSCALL_TBL_ENTRY(sys_fstatfs64),
	PROT_SYSCALL_TBL_ENTRY(sys_tgkill),
	PROT_SYSCALL_TBL_ENTRY(sys_utimes),
	PROT_SYSCALL_TBL_ENTRY(sys_fadvise64_64),	/* 310 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* old sys_vserver */
	PROT_SYSCALL_TBL_ENTRY(sys_mbind),
	PROT_SYSCALL_TBL_ENTRY(sys_get_mempolicy),
	PROT_SYSCALL_TBL_ENTRY(sys_set_mempolicy),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_open),		/* 315 */
	PROT_SYSCALL_TBL_ENTRY(sys_mq_unlink),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_timedsend),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_timedreceive),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mq_notify),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_getsetattr),	/* 320 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_kexec_load),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_waitid),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_add_key),
	PROT_SYSCALL_TBL_ENTRY(sys_request_key),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_keyctl),	/* 325 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* old sys_mcst_rt */
	PROT_SYSCALL_TBL_ENTRY(sys_getcpu),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_move_pages),
	PROT_SYSCALL_TBL_ENTRY(sys_splice),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_vmsplice),	/* 330 */
	PROT_SYSCALL_TBL_ENTRY(sys_tee),
	PROT_SYSCALL_TBL_ENTRY(sys_migrate_pages),
	PROT_SYSCALL_TBL_ENTRY(sys_utimensat),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_tgsigqueueinfo),
	PROT_SYSCALL_TBL_ENTRY(sys_openat),		/* 335 */
	PROT_SYSCALL_TBL_ENTRY(sys_mkdirat),
	PROT_SYSCALL_TBL_ENTRY(sys_mknodat),
	PROT_SYSCALL_TBL_ENTRY(sys_fchownat),
	PROT_SYSCALL_TBL_ENTRY(sys_unlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_renameat),		/* 340 */
	PROT_SYSCALL_TBL_ENTRY(sys_linkat),
	PROT_SYSCALL_TBL_ENTRY(sys_symlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_readlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_fchmodat),
	PROT_SYSCALL_TBL_ENTRY(sys_faccessat),		/* 345 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_pwait),
	PROT_SYSCALL_TBL_ENTRY(sys_signalfd4),
	PROT_SYSCALL_TBL_ENTRY(sys_eventfd2),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_recvmmsg),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* 350 */
#ifdef CONFIG_TIMERFD
	PROT_SYSCALL_TBL_ENTRY(sys_timerfd_create),
	PROT_SYSCALL_TBL_ENTRY(sys_timerfd_settime),
	PROT_SYSCALL_TBL_ENTRY(sys_timerfd_gettime),
#else
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
#endif
	PROT_SYSCALL_TBL_ENTRY(protected_sys_preadv),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_pwritev),	/* 355 */
	PROT_SYSCALL_TBL_ENTRY(sys_fallocate),
	PROT_SYSCALL_TBL_ENTRY(sys_sync_file_range),
	PROT_SYSCALL_TBL_ENTRY(sys_dup3),
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_init1),
	PROT_SYSCALL_TBL_ENTRY(sys_epoll_create1),	/* 360 */
	PROT_SYSCALL_TBL_ENTRY(sys_fstatat64),
	PROT_SYSCALL_TBL_ENTRY(sys_futimesat),
	PROT_SYSCALL_TBL_ENTRY(protected_syscall_notyetsupported),
	PROT_SYSCALL_TBL_ENTRY(sys_unshare),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_get_robust_list),	/* 365 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_set_robust_list),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_pselect6),
	PROT_SYSCALL_TBL_ENTRY(sys_ppoll),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_setcontext),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_makecontext),	/* 370 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_swapcontext),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_freecontext),
	PROT_SYSCALL_TBL_ENTRY(sys_fanotify_init),
	PROT_SYSCALL_TBL_ENTRY(sys_fanotify_mark),
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_prlimit64),		/* 375 */
	PROT_SYSCALL_TBL_ENTRY(sys_clock_adjtime),
	PROT_SYSCALL_TBL_ENTRY(sys_syncfs),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_sendmmsg),
	PROT_SYSCALL_TBL_ENTRY(sys_setns),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_process_vm_readv), /* 380 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_process_vm_writev),
	PROT_SYSCALL_TBL_ENTRY(sys_kcmp),
	PROT_SYSCALL_TBL_ENTRY(sys_finit_module),

	/* added in linux-4.4 */
	PROT_SYSCALL_TBL_ENTRY(sys_renameat2),
	PROT_SYSCALL_TBL_ENTRY(sys_getrandom),		/* 385 */
	PROT_SYSCALL_TBL_ENTRY(sys_memfd_create),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_bpf),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_execveat),
	PROT_SYSCALL_TBL_ENTRY(sys_userfaultfd),
	PROT_SYSCALL_TBL_ENTRY(sys_membarrier),		/* 390 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mlock2),

	/* added in linux-4.9 */
	PROT_SYSCALL_TBL_ENTRY(sys_seccomp),
	PROT_SYSCALL_TBL_ENTRY(sys_shutdown),
	PROT_SYSCALL_TBL_ENTRY(sys_copy_file_range),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_preadv2),	/* 395 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_pwritev2),

	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	PROT_SYSCALL_TBL_ENTRY(sys_open_by_handle_at),
	PROT_SYSCALL_TBL_ENTRY(sys_statx),

	/* added for compatibility with x86_64 */
	PROT_SYSCALL_TBL_ENTRY(sys_socket),
	PROT_SYSCALL_TBL_ENTRY(sys_connect),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_accept),		/* 405 */
	PROT_SYSCALL_TBL_ENTRY(sys_sendto),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_recvfrom),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_sendmsg),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_recvmsg),
	PROT_SYSCALL_TBL_ENTRY(sys_bind),		/* 410 */
	PROT_SYSCALL_TBL_ENTRY(sys_listen),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_getsockname),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_getpeername),
	PROT_SYSCALL_TBL_ENTRY(sys_socketpair),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_setsockopt), /* 415 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_getsockopt),

	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),

	/* protected specific system calls entries */
	PROT_SYSCALL_TBL_ENTRY(sys_arch_prctl),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_uselib),	/* 420 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigaction),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* sys_get_mem */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),		/* sys_free_mem */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_clean_descriptors),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_unuselib),	/* 425 */

	PROT_SYSCALL_TBL_ENTRY(protected_sys_clone3),
	PROT_SYSCALL_TBL_ENTRY(sys_fsopen),
	PROT_SYSCALL_TBL_ENTRY(sys_fsconfig),
	PROT_SYSCALL_TBL_ENTRY(sys_fsmount),
	PROT_SYSCALL_TBL_ENTRY(sys_fspick),		/* 430 */

	/* added for Linux 5.10 */
	PROT_SYSCALL_TBL_ENTRY(sys_close_range),
	PROT_SYSCALL_TBL_ENTRY(sys_openat2),
	PROT_SYSCALL_TBL_ENTRY(sys_pidfd_getfd),
	PROT_SYSCALL_TBL_ENTRY(sys_faccessat2),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_process_madvise), /* 435 */

	/* added for Linux 5.15 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_pwait2),
	PROT_SYSCALL_TBL_ENTRY(sys_mount_setattr),
	PROT_SYSCALL_TBL_ENTRY(sys_quotactl_fd),
	PROT_SYSCALL_TBL_ENTRY(sys_landlock_create_ruleset),
	PROT_SYSCALL_TBL_ENTRY(sys_landlock_add_rule),		/* 440 */
	PROT_SYSCALL_TBL_ENTRY(sys_landlock_restrict_self),
	PROT_SYSCALL_TBL_ENTRY(sys_process_mrelease),

	/* added for Linux 6.1 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_futex_waitv),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_set_mempolicy_home_node),

	/* added for soft secure (unsafe) protected mode */
	PROT_SYSCALL_TBL_ENTRY(sys_unsafe_uint64_to_ptr),

	/* 445 last System call */
};
#endif /* CONFIG_PROTECTED_MODE */

/* For the deprecated 4th syscall entry.
 * Since this system call entry is deprecated we use
 * sys_ni_syscall for all new entries from now on. */
const system_call_func sys_call_table_deprecated[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_restart_syscall),	/* 0 */
	SYSTEM_CALL_TBL_ENTRY(sys_exit),
	SYSTEM_CALL_TBL_ENTRY(sys_fork),
	SYSTEM_CALL_TBL_ENTRY(sys_read),
	SYSTEM_CALL_TBL_ENTRY(sys_write),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_open),	/* 5 */
	SYSTEM_CALL_TBL_ENTRY(sys_close),
	SYSTEM_CALL_TBL_ENTRY(sys_waitpid),
	SYSTEM_CALL_TBL_ENTRY(sys_creat),
	SYSTEM_CALL_TBL_ENTRY(sys_link),
	SYSTEM_CALL_TBL_ENTRY(sys_unlink),	/* 10 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_break */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime32),	/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stty */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_gtty */
	SYSTEM_CALL_TBL_ENTRY(sys_access),
	SYSTEM_CALL_TBL_ENTRY(sys_nice),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old ftime syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_sync),
	SYSTEM_CALL_TBL_ENTRY(sys_kill),
	SYSTEM_CALL_TBL_ENTRY(sys_rename),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdir),
	SYSTEM_CALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	SYSTEM_CALL_TBL_ENTRY(sys_dup),
	SYSTEM_CALL_TBL_ENTRY(sys_pipe),
	SYSTEM_CALL_TBL_ENTRY(sys_times),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_prof */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_signal, have to be */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lock */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),/* 55 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_mpx */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_ulimit */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_oldolduname */
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigaction(), use */
						/* sys_rt_sigaction() instead */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigsuspend */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_select */
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat */
	SYSTEM_CALL_TBL_ENTRY(sys_readlink),	/* 85 */
	SYSTEM_CALL_TBL_ENTRY(sys_uselib),
	SYSTEM_CALL_TBL_ENTRY(sys_swapon),
	SYSTEM_CALL_TBL_ENTRY(sys_reboot),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_old_readdir),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap),	/* 90 */
	SYSTEM_CALL_TBL_ENTRY(sys_munmap),
	SYSTEM_CALL_TBL_ENTRY(sys_truncate),
	SYSTEM_CALL_TBL_ENTRY(sys_ftruncate),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmod),
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),	/* 95 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_setpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_profil */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs),	/* 100 */
	SYSTEM_CALL_TBL_ENTRY(sys_ioperm),
	SYSTEM_CALL_TBL_ENTRY(sys_socketcall),
	SYSTEM_CALL_TBL_ENTRY(sys_syslog),
	SYSTEM_CALL_TBL_ENTRY(sys_setitimer),
	SYSTEM_CALL_TBL_ENTRY(sys_getitimer),	/* 105 */
	SYSTEM_CALL_TBL_ENTRY(sys_newstat),	/* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newlstat),	/* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newfstat),   
	SYSTEM_CALL_TBL_ENTRY(sys_uname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_idle */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86old */
	SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sigreturn */
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_create_module */
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 130, old sys_get_kernel_syms */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_llseek),	/* 140 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents),
	SYSTEM_CALL_TBL_ENTRY(sys_select),
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	SYSTEM_CALL_TBL_ENTRY(sys_readv),	/* 145 */
	SYSTEM_CALL_TBL_ENTRY(sys_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_sysctl */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),		/* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),	/* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_vm86 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_query_module */
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_nfsservctl */
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_prctl),
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),	/* sys_rt_sigreturn() */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigaction),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigtimedwait_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigsuspend),
#ifdef CONFIG_COMPAT
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_getpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_putpmsg */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

#ifdef CONFIG_COMPAT
	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64),
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195, in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_lstat64),     /* in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_fstat64),     /* in libc used in ptr32 mode */

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),

	/*
	 * They are used for back compatibility
	 */
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 210 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),	/* 215 */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),

	SYSTEM_CALL_TBL_ENTRY(sys_pivot_root),
	SYSTEM_CALL_TBL_ENTRY(sys_mincore),
	SYSTEM_CALL_TBL_ENTRY(sys_madvise),
	SYSTEM_CALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),/*
						 * sys_fcntl used if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_core */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225, old sys_emergency */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /* old sys_e2k_longjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2),/* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_soft_debug */
	SYSTEM_CALL_TBL_ENTRY(sys_setxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fsetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_getxattr),	/* 235 */
	SYSTEM_CALL_TBL_ENTRY(sys_lgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fgetxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_listxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_llistxattr),
	SYSTEM_CALL_TBL_ENTRY(sys_flistxattr),	/* 240 */
	SYSTEM_CALL_TBL_ENTRY(sys_removexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_fremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_gettid),
#ifdef CONFIG_COMPAT
	SYSTEM_CALL_TBL_ENTRY(sys32_readahead),	/* 245 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_tkill),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
#if defined CONFIG_FUTEX
	SYSTEM_CALL_TBL_ENTRY(sys_futex_time32),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_setaffinity),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary),	/* 260 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */	
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_create),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_settime32),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_gettime32),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_getoverrun),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_delete),/* 265 */
	SYSTEM_CALL_TBL_ENTRY(sys_clock_settime32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_gettime32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_getres_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_nanosleep_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 270 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 275 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 280 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 285 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),  /* 295 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents_time32), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
#ifdef CONFIG_COMPAT
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group),	/* 300 */
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait),
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages),	/* 305 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes_time32), 
#ifdef CONFIG_COMPAT
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64),	/* 310 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* old sys_vserver */
	SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),	/* 315 */
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr),/* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_keyctl),	/* 325 */

	/* This system call entry is deprecated so use
	 * sys_ni_syscall for all entries from now on. */
	[__NR_keyctl + 1 ... NR_syscalls - 1] = SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall)
};

/*
 * System call name table:
 */
const char *sys_call_ID_to_name[NR_syscalls] = {
	"restart_syscall",	/* 0 */
	"exit",
	"fork",
	"read",
	"write",
	"open",		/* 5 */
	"close",
	"waitpid",
	"creat",
	"link",
	"unlink",	/* 10 */
	"execve",
	"chdir",
	"time",
	"mknod",
	"chmod",	/* 15 */
	"lchown",
	"old_break",	/* place holder / ni_syscall */
	"old_stat",	/* ditto */
	"lseek",
	"getpid",	/* 20 */
	"mount",
	"oldumount",
	"setuid",
	"getuid",
	"stime",	/* 25 */
	"ptrace",
	"alarm",
	"old_fstat",	/* place holder / ni_syscal */
	"pause",
	"utime",	/* 30 */
	"old_stty",	/* place holder / ni_syscal */
	"old_gtty",	/* ditto */
	"access",
	"nice",
	"old_ftime",	/* 35, place holder / ni_syscal */
	"sync",
	"kill",
	"rename",
	"mkdir",
	"rmdir",	/* 40 */
	"dup",
	"pipe",
	"times",
	"old_prof",	/* place holder / ni_syscal */
	"brk",		/* 45 */
	"setgid",
	"getgid",
	"signal",	/* place holder / ni_syscal / to be emulated by rt_sigaction() */
	"geteuid",
	"getegid",	/* 50 */
	"acct",
	"umount",	/* recycled never used phys() */
	"old_lock",	/* old lock syscall holder */
	"ioctl",
	"fcntl",	/* 55 */
	"old_mpx",	/* place holder / ni_syscal */
	"setpgid",
	"old_ulimit",	/* place holder / ni_syscal */
	"old_olduname",	/* ditto */
	"umask",	/* 60 */
	"chroot",
	"ustat",
	"dup2",
	"getppid",
	"getpgrp",	/* 65 */
	"setsid",
	"sigaction",	/* no sys_sigaction() */
	"sgetmask",
	"ssetmask",
	"setreuid",	/* 70 */
	"setregid",
	"sigsuspend",	/* place holder / ni_syscal */
	"sigpending",
	"sethostname",
	"setrlimit",	/* 75 */
	"old_getrlimit",
	"getrusage",
	"gettimeofday",
	"settimeofday",
	"getgroups",	/* 80 */
	"setgroups",
	"old_select",
	"symlink",
	"old_lstat",	/* place holder / ni_syscal */
	"readlink",	/* 85 */
	"uselib",
	"swapon",
	"reboot",
	"old_readdir",
	"mmap",		/* 90 */
	"munmap",
	"truncate",
	"ftruncate",
	"fchmod",
	"fchown",	/* 95 */
	"getpriority",
	"setpriority",
	"old_profil",	/* place holder / ni_syscal */
	"statfs",
	"fstatfs",	/* 100 */
	"ioperm",
	"socketcall",
	"syslog",
	"setitimer",
	"getitimer",	/* 105 */
	"newstat",	/* in libc used in ptr64 mode */
	"newlstat",	/* in libc used in ptr64 mode */
	"newfstat",	/* in libc used in ptr64 mode */
	"uname",
	"iopl",		/* 110 */
	"vhangup",
	"old_idle",	/* place holder / ni_syscal */
	"vm86old",	/* ditto */
	"wait4",
	"swapoff",	/* 115 */
	"sysinfo",
	"ipc",
	"fsync",
	"sigreturn",	/* place holder / ni_syscal */
	"clone",	/* 120 */
	"setdomainname",
	"newuname",
	"modify_ldt",	/* place holder / ni_syscal */
	"adjtimex",
	"mprotect",	/* 125 */
	"sigprocmask",
	"create_module",	/* place holder / ni_syscal */
	"init_module",
	"delete_module",
	"get_kernel_syms",	/* 130 / place holder / ni_syscal */
	"quotactl",
	"getpgid",
	"fchdir",
	"bdflush",
	"sysfs",	/* 135 - obsolete */
	"personality",
	"old_afs",	/* place holder / ni_syscal */
	"setfsuid",
	"setfsgid",
	"llseek",	/* 140 */
	"getdents",
	"select",
	"flock",
	"msync",
	"readv",	/* 145 */
	"writev",
	"getsid",
	"fdatasync",
	"_sysctl",
	"mlock",	/* 150 */
	"munlock",
	"mlockall",
	"munlockall",
	"sched_setparam",
	"sched_getparam",   /* 155 */
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_yield",
	"sched_get_priority_max",
	"sched_get_priority_min",  /* 160 */
	"sched_rr_get_interval",
	"nanosleep",
	"mremap",
	"setresuid",
	"getresuid",	/* 165 */
	"vm86",		/* place holder / ni_syscal */
	"query_module",	/* ditto */
	"poll",
	"nfsservctl",	/* 169 place holder / ni_syscal */
	"setresgid",	/* 170 */
	"getresgid",
	"prctl",
	"rt_sigreturn",	/* 173 */
	"rt_sigaction",
	"rt_sigprocmask",	/* 175 */
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"pread64",	/* 180 */
	"pwrite64",
	"chown",
	"getcwd",
	"capget",
	"capset",	/* 185 */
	"sigaltstack",
	"sendfile64",
	"getpmsg",	/* 188 place holder / ni_syscal */
	"putpmsg",	/* 189 place holder / ni_syscal */
	"vfork",	/* 190 */
	"getrlimit",
	"mmap2",

	/* Entries 193-194 are for BITS_PER_LONG == 32; and this is 64 bit OS */
	"truncate64",	/* 193 place holder / ni_syscal */
	"ftruncate64",	/* 194 ditto	*/

	"stat64",	/* 195 */
	"lstat64",
	"fstat64",
	"lchown",
	"getuid32",
	"getgid32",	/* 200 */
	"geteuid32",
	"getegid32",
	"setreuid32",
	"setregid32",
	"pidfd_send_signal",	/* 205 */
	"pidfd_open",
	"fchown",
	"setresuid32",
	"getresuid32",
	"setresgid32",	/* 210 */
	"getresgid32",
	"chown",
	"setuid",
	"setgid",
	"setfsuid",	/* 215 */
	"setfsgid",
	"pivot_root",
	"mincore",
	"madvise",
	"getdents64",	/* 220 */
	"fcntl64",	/* 221 */
	"core",		/* place holder / ni_syscal */
	"RESERVED",	/* 223 */
	"newfstatat",
	"emergency",	/* 225 place holder / ni_syscal */
	"e2k_setjmp",	/* ditto */
	"e2k_longjmp",	/* ditto */
	"e2k_syswork",
	"clone_thread",
	"e2k_longjmp2", /* 230 */
	"soft_debug",	/* place holder / ni_syscal */
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",	/* 235 */
	"lgetxattr",
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",	/* 240 */
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"gettid",
	"readahead",	/* 245 */
	"tkill",
	"sendfile64",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",	/* 250 */
	"pipe2",
	"set_backtrace",
	"get_backtrace",
	"access_hw_stacks",
	"RESERVED",	/* 255 */
	"io_uring_setup",
	"io_uring_enter",
	"io_uring_register",
	"set_tid_address",
	"el_binary",	/* 260 */
	"timer_create",
	"timer_settime",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",	/* 265 */
	"clock_settime",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"msgget",	/* 270 */
	"msgctl",
	"msgrcv",
	"msgsnd",
	"semget",
	"semctl",	/* 275 */
	"semtimedop",
	"semop",
	"shmget",
	"shmctl",
	"shmat",	/* 280 */
	"shmdt",
	"open_tree",
	"move_mount",
	"rseq",
	"io_pgetevents", /* 285 */
	"accept4",
	"sched_setattr",
	"sched_getattr",
	"ioprio_set",	/* 289 */
	"ioprio_get",	/* 290 */
	"inotify_init",	/* 291 */
	"inotify_add_watch",
	"inotify_rm_watch",
	"io_setup",	/* 294 */
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"fadvise64",
	"exit_group",	/* 300 */
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl",
	"epoll_wait",
	"remap_file_pages",
	"statfs64",
	"fstatfs64",
	"tgkill",
	"utimes",
	"fadvise64_64",	/* 310 */
	"vserver",	/* place holder / ni_syscal isn't implemented in the Linux 2.6.14 kernel */
	"mbind",
	"get_mempolicy",
	"set_mempolicy",
	"mq_open",
	"mq_unlink",
	"mq_timedsend",
	"mq_timedreceive",
	"mq_notify",
	"mq_getsetattr", /* 320 */
	"kexec_load",
	"waitid",
	"add_key",
	"request_key",
	"keyctl",
	"mcst_rt",	/* place holder / ni_syscal */
	"getcpu",
	"move_pages",
	"splice",
	"vmsplice",	/* 330 */
	"tee",
	"migrate_pages",
	"utimensat",
	"rt_tgsigqueueinfo",
	"openat",
	"mkdirat",
	"mknodat",
	"fchownat",
	"unlinkat",
	"renameat",	/* 340 */
	"linkat",
	"symlinkat",
	"readlinkat",
	"fchmodat",
	"faccessat",
	"epoll_pwait",
	"signalfd4",
	"eventfd2",
	"recvmmsg",
	"RESERVED",	/* 350 - ni_syscal */
	"timerfd_create",
	"timerfd_settime",
	"timerfd_gettime",
	"preadv",
	"pwritev",
	"fallocate",
	"sync_file_range",
	"dup3",
	"inotify_init1",
	"epoll_create1",	/* 360 */
	"fstatat64",
	"futimesat",
	"perf_event_open",
	"unshare",
	"get_robust_list",	/* 365 */
	"set_robust_list",
	"pselect6",
	"ppoll",
	"setcontext",
	"makecontext",		/* 370 */
	"swapcontext",
	"freecontext",
	"fanotify_init",
	"fanotify_mark",
	"prlimit64",
	"clock_adjtime",
	"syncfs",
	"sendmmsg",
	"setns",
	"process_vm_readv",	/* 380 */
	"process_vm_writev",
	"kcmp",
	"finit_module",

	/* added in linux-4.4 */
	"renameat2",
	"getrandom",		/* 385 */
	"memfd_create",
	"bpf",
	"execveat",
	"userfaultfd",
	"membarrier",		/* 390 */
	"mlock2",

	/* added in linux-4.9 */
	"seccomp",
	"shutdown",
	"copy_file_range",
	"preadv2",		/* 395 */
	"pwritev2",

	/* free (unused) items */
	"RESERVED",		/* 397 - ni_syscall */
	"RESERVED",		/* 398 - ni_syscall */
	"RESERVED",		/* 399 - ni_syscall */

	"name_to_handle_at",	/* 400 */
	"open_by_handle_at",	/* 401 */
	"statx",		/* 402 */

	/* added for compatibility with x86_64 */
	"socket",	/* 403 */
	"connect",	/* 404 */
	"accept",	/* 405 */
	"sendto",	/* 406 */
	"recvfrom",	/* 407 */
	"sendmsg",	/* 408 */
	"recvmsg",	/* 409 */
	"bind",		/* 410 */
	"listen",	/* 411 */
	"getsockname",	/* 412 */
	"getpeername",	/* 413 */
	"socketpair",	/* 414 */
	"setsockopt",	/* 415 */
	"getsockopt",	/* 416 */

	/* free (unused) items */
	"RESERVED",	/* 417 - ni_syscall */
	"RESERVED",	/* 418 - ni_syscall */

	/* protected specific system calls entries */
	"arch_prctl",
	"newuselib",		/* 420 */
	"rt_sigaction_ex",
	"get_mem",
	"free_mem",
	"clean_descriptors",
	"unuselib",		/* 425 */

	"clone3",
	"fsopen",
	"fsconfig",
	"fsmount",
	"fspick",		/* 430 */

	/* added for Linux 5.10 */
	"close_range",
	"openat2",
	"pidfd_getfd",
	"faccessat2",
	"process_madvise",	/* 435 */

	/* added for Linux 5.10 */
	"epoll_pwait2",
	"mount_setattr",
	"quotactl_fd",
	"landlock_create_ruleset",
	"landlock_add_rule",
	"landlock_restrict_self",
	"process_mrelease",

	/* added for Linux 6.1 */
	"futex_waitv",
	"set_mempolicy_home_node",
	"unsafe_uint64_to_ptr"
};
