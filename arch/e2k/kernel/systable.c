/* linux/arch/e2k/kernel/systable.c, v 1.1 05/28/2001.
 *
 * Copyright (C) 2001 MCST
 */

#include <linux/syscalls.h>
#include <linux/compat.h>

#include <asm/syscalls.h>
#include <asm/trap_table.h>

#define	SYSTEM_CALL_TBL_ENTRY(sysname)	(system_call_func) sysname
#define	PROT_SYSCALL_TBL_ENTRY(sysname)	((protected_system_call_func) sysname)

#ifdef CONFIG_COMPAT
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(system_call_func) compat_##sysname
#else
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(system_call_func) sys_ni_syscall
#endif


asmlinkage long sys_deprecated(void)
{
	pr_info_ratelimited("System call #%d/$s is obsolete\n",
			current_pt_regs()->sys_num);

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
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old break syscall holder */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat() */
	SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime),	/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old stty syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old gtty syscall holder */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old prof syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* signal() have to be        */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),	/* recycled never used phys() */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old lock syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	/* 55 */ /* for 64 & 32 */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old mpx syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old ulimit syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* no sys_sigaction(), use    */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),	/* sys_rt_sigaction() instead */
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_old_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat() */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old profil syscall holder */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old "idle" system call */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_bdflush),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* for afs_syscall */
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
	SYSTEM_CALL_TBL_ENTRY(sys_sysctl),
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),   /* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),  /* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* was sys_nfsservctl */
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
	SYSTEM_CALL_TBL_ENTRY(sys_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), 
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
						/* 
						 * 193 & 194 entries are
						 * sys_truncate64 &
						 * sys_ftruncate64 in open.c
						 * if OS is for
						 * BITS_PER_LONG == 32
						 * Our OS is for 64
						 */
	
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195 , in libc used in ptr32 mode */
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
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
	SYSTEM_CALL_TBL_ENTRY(sys_newfstatat),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_longjmp*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2), /* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix), /* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_enter),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_register),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_msgget),	/* 270 */
	SYSTEM_CALL_TBL_ENTRY(sys_msgctl),
	SYSTEM_CALL_TBL_ENTRY(sys_msgrcv),
	SYSTEM_CALL_TBL_ENTRY(sys_msgsnd),
	SYSTEM_CALL_TBL_ENTRY(sys_semget),
	SYSTEM_CALL_TBL_ENTRY(sys_old_semctl),	/* 275 */
	SYSTEM_CALL_TBL_ENTRY(sys_semtimedop),
	SYSTEM_CALL_TBL_ENTRY(sys_semop),
	SYSTEM_CALL_TBL_ENTRY(sys_shmget),
	SYSTEM_CALL_TBL_ENTRY(sys_shmctl),
	SYSTEM_CALL_TBL_ENTRY(sys_shmat),	/* 280 */
	SYSTEM_CALL_TBL_ENTRY(sys_shmdt),
	SYSTEM_CALL_TBL_ENTRY(sys_open_tree),
	SYSTEM_CALL_TBL_ENTRY(sys_move_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_rseq),
	SYSTEM_CALL_TBL_ENTRY(sys_io_pgetevents), /* 285 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept4),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setattr),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getattr),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),	/* 289 __NR_ioprio_set */
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 __NR_ioprio_get */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),/* 291 __NR_inotify_init */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
						/* 292 __NR_inotify_add_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
						/* 293 __NR_inotify_rm_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_io_setup),    /* 294 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
	SYSTEM_CALL_TBL_ENTRY(sys_fadvise64),  
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group), /* 300 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait), 
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages), 
	SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes), 
	SYSTEM_CALL_TBL_ENTRY(sys_fadvise64_64), /* 310 */
        
        SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */ 
                                          /*The system call isn't implemented in the Linux 2.6.14
                                             * kernel  */
	SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_open),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
	SYSTEM_CALL_TBL_ENTRY(sys_keyctl),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_mcst_rt */
	SYSTEM_CALL_TBL_ENTRY(sys_getcpu),
	SYSTEM_CALL_TBL_ENTRY(sys_move_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_splice),
	SYSTEM_CALL_TBL_ENTRY(sys_vmsplice),	/* 330 */
	SYSTEM_CALL_TBL_ENTRY(sys_tee),
	SYSTEM_CALL_TBL_ENTRY(sys_migrate_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_utimensat),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_tgsigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_openat),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdirat),
	SYSTEM_CALL_TBL_ENTRY(sys_mknodat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchownat),
	SYSTEM_CALL_TBL_ENTRY(sys_unlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_renameat),	/* 340 */
	SYSTEM_CALL_TBL_ENTRY(sys_linkat),
	SYSTEM_CALL_TBL_ENTRY(sys_symlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_readlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmodat),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat),
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
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev),
	SYSTEM_CALL_TBL_ENTRY(sys_fallocate),
	SYSTEM_CALL_TBL_ENTRY(sys_sync_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat),
	SYSTEM_CALL_TBL_ENTRY(sys_perf_event_open),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	SYSTEM_CALL_TBL_ENTRY(sys_get_robust_list),
	SYSTEM_CALL_TBL_ENTRY(sys_set_robust_list),
	SYSTEM_CALL_TBL_ENTRY(sys_pselect6),
	SYSTEM_CALL_TBL_ENTRY(sys_ppoll),
	SYSTEM_CALL_TBL_ENTRY(sys_setcontext),
	SYSTEM_CALL_TBL_ENTRY(sys_makecontext),	/* 370 */
	SYSTEM_CALL_TBL_ENTRY(sys_swapcontext),
	SYSTEM_CALL_TBL_ENTRY(sys_freecontext),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_init),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_mark),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_prlimit64),
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
	SYSTEM_CALL_TBL_ENTRY(sys_getrandom),
	SYSTEM_CALL_TBL_ENTRY(sys_memfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_bpf),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_execveat),
	SYSTEM_CALL_TBL_ENTRY(sys_userfaultfd),
	SYSTEM_CALL_TBL_ENTRY(sys_membarrier),		/* 390 */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock2),
	/* added in linux-4.9 */
	SYSTEM_CALL_TBL_ENTRY(sys_seccomp),
	SYSTEM_CALL_TBL_ENTRY(sys_shutdown),
	SYSTEM_CALL_TBL_ENTRY(sys_copy_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_preadv2),
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev2),

	/* free (unused) items */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),

	SYSTEM_CALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	SYSTEM_CALL_TBL_ENTRY(sys_open_by_handle_at),	/* 401 */
	SYSTEM_CALL_TBL_ENTRY(sys_statx),		/* 402 */
	/* added for compatibility with x86_64 */
	SYSTEM_CALL_TBL_ENTRY(sys_socket),		/* 403 */
	SYSTEM_CALL_TBL_ENTRY(sys_connect),		/* 404 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept),	/* 405 */
	SYSTEM_CALL_TBL_ENTRY(sys_sendto),		/* 406 */
	SYSTEM_CALL_TBL_ENTRY(sys_recvfrom),		/* 407 */
	SYSTEM_CALL_TBL_ENTRY(sys_sendmsg),		/* 408 */
	SYSTEM_CALL_TBL_ENTRY(sys_recvmsg),		/* 409 */
	SYSTEM_CALL_TBL_ENTRY(sys_bind),	/* 410 */
	SYSTEM_CALL_TBL_ENTRY(sys_listen),		/* 411 */
	SYSTEM_CALL_TBL_ENTRY(sys_getsockname),		/* 412 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpeername),		/* 413 */
	SYSTEM_CALL_TBL_ENTRY(sys_socketpair),		/* 414 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsockopt),	/* 415 */
	SYSTEM_CALL_TBL_ENTRY(sys_getsockopt),		/* 416 */

	/* free (unused) items */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 417 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 418 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 419 */

	/* protected specific system calls entries */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 420 __NR_newuselib */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 421 __NR_rt_sigaction_ex */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 422 __NR_get_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 423 __NR_free_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 424 __NR_clean_descriptors */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 425 __NR_unuselib */

	SYSTEM_CALL_TBL_ENTRY(sys_clone3),
	SYSTEM_CALL_TBL_ENTRY(sys_fsopen),
	SYSTEM_CALL_TBL_ENTRY(sys_fsconfig),
	SYSTEM_CALL_TBL_ENTRY(sys_fsmount),
	SYSTEM_CALL_TBL_ENTRY(sys_fspick),	/* 430 */
};

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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old break syscall holder */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat() */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime32),	/* 25 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime32),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old stty syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old gtty syscall holder */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_times),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old prof syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* signal() have to be        */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),	/* recycled never used phys() */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old lock syscall holder */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),/* 55 */ /* for 64 & 32 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old mpx syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old ulimit syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* no sys_sigaction(), use    */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),	/* sys_rt_sigaction() instead */
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat() */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old profil syscall holder */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old "idle" system call */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_bdflush),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* for afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_llseek),	/* 140 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_select),
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_readv),	/* 145 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sysctl),
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),   /* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),  /* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* was sys_nfsservctl */
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
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64), 
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195 , in libc used in ptr32 mode */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl64),	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_longjmp*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2), /* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix),	/* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_setup),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_enter),
	SYSTEM_CALL_TBL_ENTRY(sys_io_uring_register),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_old_semctl),	/* 275 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),	/* 289 __NR_ioprio_set */
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 __NR_ioprio_get */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),/* 291 __NR_inotify_init */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
						/* 292 __NR_inotify_add_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
						/* 293 __NR_inotify_rm_watch */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_setup),    /* 294 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64),  
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group), /* 300 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait), 
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes_time32),
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64), /* 310 */
        
        SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */ 
                                          /*The system call isn't implemented in the Linux 2.6.14
                                             * kernel  */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
#ifdef CONFIG_KEYS_COMPAT
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_keyctl),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_mcst_rt */
	SYSTEM_CALL_TBL_ENTRY(sys_getcpu),
	SYSTEM_CALL_TBL_ENTRY(sys_move_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_splice),
	SYSTEM_CALL_TBL_ENTRY(sys_vmsplice),	/* 330 */
	SYSTEM_CALL_TBL_ENTRY(sys_tee),
	SYSTEM_CALL_TBL_ENTRY(sys_migrate_pages),
	SYSTEM_CALL_TBL_ENTRY(sys_utimensat_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_tgsigqueueinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_openat),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdirat),
	SYSTEM_CALL_TBL_ENTRY(sys_mknodat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchownat),
	SYSTEM_CALL_TBL_ENTRY(sys_unlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_renameat),	/* 340 */
	SYSTEM_CALL_TBL_ENTRY(sys_linkat),
	SYSTEM_CALL_TBL_ENTRY(sys_symlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_readlinkat),
	SYSTEM_CALL_TBL_ENTRY(sys_fchmodat),
	SYSTEM_CALL_TBL_ENTRY(sys_faccessat),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_pwait),
#ifdef CONFIG_SIGNALFD
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_signalfd4),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_eventfd2),
	SYSTEM_CALL_TBL_ENTRY(sys_recvmmsg_time32),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pwritev),
	SYSTEM_CALL_TBL_ENTRY(sys32_fallocate),
	SYSTEM_CALL_TBL_ENTRY(sys32_sync_file_range),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_perf_event_open),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_robust_list),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_robust_list),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pselect6_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ppoll_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_setcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_makecontext),	/* 370 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_swapcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_freecontext),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_init),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fanotify_mark),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_prlimit64),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_adjtime32),
	SYSTEM_CALL_TBL_ENTRY(sys_syncfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_setns),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_process_vm_readv), /* 380 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_process_vm_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_kcmp),
	SYSTEM_CALL_TBL_ENTRY(sys_finit_module),
	/* added in linux-4.4 */
	SYSTEM_CALL_TBL_ENTRY(sys_renameat2),
	SYSTEM_CALL_TBL_ENTRY(sys_getrandom),
	SYSTEM_CALL_TBL_ENTRY(sys_memfd_create),
	SYSTEM_CALL_TBL_ENTRY(sys_bpf),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_execveat),
	SYSTEM_CALL_TBL_ENTRY(sys_userfaultfd),
	SYSTEM_CALL_TBL_ENTRY(sys_membarrier),		/* 390 */
	SYSTEM_CALL_TBL_ENTRY(sys_mlock2),
	/* added in linux-4.9 */
	SYSTEM_CALL_TBL_ENTRY(sys_seccomp),
	SYSTEM_CALL_TBL_ENTRY(sys_shutdown),
	SYSTEM_CALL_TBL_ENTRY(sys_copy_file_range),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_preadv2),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pwritev2),

	/* free (unused) items */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),

	SYSTEM_CALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_open_by_handle_at),
	SYSTEM_CALL_TBL_ENTRY(sys_statx),		/* 402 */

	/* added for compatibility with x86_64 */
	SYSTEM_CALL_TBL_ENTRY(sys_socket),		/* 403 */
	SYSTEM_CALL_TBL_ENTRY(sys_connect),		/* 404 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept),		/* 405 */
	SYSTEM_CALL_TBL_ENTRY(sys_sendto),		/* 406 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvfrom),	/* 407 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendmsg),	/* 408 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvmsg),	/* 409 */
	SYSTEM_CALL_TBL_ENTRY(sys_bind),		/* 410 */
	SYSTEM_CALL_TBL_ENTRY(sys_listen),		/* 411 */
	SYSTEM_CALL_TBL_ENTRY(sys_getsockname),		/* 412 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpeername),		/* 413 */
	SYSTEM_CALL_TBL_ENTRY(sys_socketpair),		/* 414 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_setsockopt),	/* 415 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getsockopt),	/* 416 */

	/* free (unused) items */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 417 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 418 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 419 */

	/* protected specific system calls entries */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 420 __NR_newuselib */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 421 __NR_rt_sigaction_ex */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 422 __NR_get_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 423 __NR_free_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 424 __NR_clean_descriptors */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 425 __NR_unuselib */

	SYSTEM_CALL_TBL_ENTRY(sys_clone3),
	SYSTEM_CALL_TBL_ENTRY(sys_fsopen),
	SYSTEM_CALL_TBL_ENTRY(sys_fsconfig),
	SYSTEM_CALL_TBL_ENTRY(sys_fsmount),
	SYSTEM_CALL_TBL_ENTRY(sys_fspick),	/* 430 */
};

/* System call handlers for protected mode (entry 10). If some system
 * call is not here it does not mean it is not implemented -
 * it is probably called from ttable_entry10 after reading
 * and preparing its parameters. */
const system_call_func sys_protcall_table[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 0 */
	SYSTEM_CALL_TBL_ENTRY(sys_exit),
	SYSTEM_CALL_TBL_ENTRY(sys_fork),		// fork
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// read
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// write
	SYSTEM_CALL_TBL_ENTRY(sys_open),	/* 5 */
	SYSTEM_CALL_TBL_ENTRY(sys_close),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// waitpid
	SYSTEM_CALL_TBL_ENTRY(sys_creat),
	SYSTEM_CALL_TBL_ENTRY(sys_link),
	SYSTEM_CALL_TBL_ENTRY(sys_unlink),	/* 10 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// time
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old break syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat() */
	SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime),	/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime),	/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old stty syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old gtty syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_access),
	SYSTEM_CALL_TBL_ENTRY(sys_nice),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old ftime syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_sync),
	SYSTEM_CALL_TBL_ENTRY(sys_kill),
	SYSTEM_CALL_TBL_ENTRY(sys_rename),
	SYSTEM_CALL_TBL_ENTRY(sys_mkdir),
	SYSTEM_CALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	SYSTEM_CALL_TBL_ENTRY(sys_dup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// pipe
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// times
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old prof syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		/* 45 */ // brk
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* signal() have to be        */
	/* emulated by rt_sigaction() */
	/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),	/* recycled never used phys() */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old lock syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	/* 55 */ /* for 64 & 32 */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old mpx syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old ulimit syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// ustat
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* no sys_sigaction(), use    */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),	/* sys_rt_sigaction() instead */
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sigpending, use rt_*
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_old_getrlimit, use u*
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getrusage
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_gettimeofday
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 80 */	// sys_getgroups
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 85 */	// sys_readlink
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	// sys_uselib
	SYSTEM_CALL_TBL_ENTRY(sys_swapon),
	SYSTEM_CALL_TBL_ENTRY(sys_reboot),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	// old_readdir
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 90 */	 // sys_mmap
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),			// sys_munmap
	
	SYSTEM_CALL_TBL_ENTRY(sys_truncate),
	SYSTEM_CALL_TBL_ENTRY(sys_ftruncate),

	SYSTEM_CALL_TBL_ENTRY(sys_fchmod),
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),	/* 95 */
	SYSTEM_CALL_TBL_ENTRY(sys_getpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_setpriority),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old profil syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_statfs
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 100 */	// sys_fstatfs
	SYSTEM_CALL_TBL_ENTRY(sys_ioperm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_socketcall
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_syslog
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_setitimer
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 105 */	// sys_getitimer

			/* next 3 calls realized in libc in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_newstat
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_newlstat
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_newfstat

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_uname - old ni
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old "idle" system call */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_wait4
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sysinfo
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// ipc
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_clone
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_setdomainname
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_newuname
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_adjtimex
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_mprotect
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sigprocmask - ni, see rt*
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_init_module
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),	// sys_delete_module
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_bdflush),		// sys_bdflush
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sysfs
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* for afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_llseek
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getdents
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_select
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	SYSTEM_CALL_TBL_ENTRY(sys_readv),		// sys_readv
	SYSTEM_CALL_TBL_ENTRY(sys_writev),		// sys_writev
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sysctl
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sched_setparam
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sched_getparam
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),  /* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sched_rr_get_interval
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_nanosleep
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_mremap
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 168 sys_poll		*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 169 sys_nfsservctl	*/
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_prctl
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 173 sys_rt_sigreturn	*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigaction
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigprocmask
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigpending
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigtimedwait
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigqueueinfo
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_rt_sigsuspend
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_pread64
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_pwrite64
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getcwd
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sigaltstack
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getrlimit
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_mmap2

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), 
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	/* 
	 * 193 & 194 entries are
	 * sys_truncate64 &
	 * sys_ftruncate64 in open.c
	 * if OS is for
	 * BITS_PER_LONG == 32
	 * Our OS is for 64
	 */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_stat64
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_lstat64
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_fstat64

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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_mincore
	SYSTEM_CALL_TBL_ENTRY(sys_madvise),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getdents64
	SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	/* sys_fcntl */
						/* 
	* 221 is sys_fcntl64 in fcntl.c
	* if BITS_PER_LONG == 32
	* for some other archs 
						*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_longjmp*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone_thread */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 230 */

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_setxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		//sys_lsetxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		//sys_fsetxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_lgetxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_fgetxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		//sys_listxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		//sys_llistxattr
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_flistxattr
	SYSTEM_CALL_TBL_ENTRY(sys_removexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_lremovexattr),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_fremovexattr
	SYSTEM_CALL_TBL_ENTRY(sys_gettid),
	SYSTEM_CALL_TBL_ENTRY(sys_readahead),	/* 245 */
	SYSTEM_CALL_TBL_ENTRY(sys_tkill),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_futex
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sched_setaffinity
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_sched_getaffinity
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 251 pipe2 */
	SYSTEM_CALL_TBL_ENTRY(sys_set_backtrace),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_access_hw_stacks),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_el_posix
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 256 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 265 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_msgget),	/* 270 */
	SYSTEM_CALL_TBL_ENTRY(sys_msgctl),
	SYSTEM_CALL_TBL_ENTRY(sys_msgrcv),
	SYSTEM_CALL_TBL_ENTRY(sys_msgsnd),
	SYSTEM_CALL_TBL_ENTRY(sys_semget),
	SYSTEM_CALL_TBL_ENTRY(sys_old_semctl),	/* 275 */
	SYSTEM_CALL_TBL_ENTRY(sys_semtimedop),
	SYSTEM_CALL_TBL_ENTRY(sys_semop),
	SYSTEM_CALL_TBL_ENTRY(sys_shmget),
	SYSTEM_CALL_TBL_ENTRY(sys_shmctl),
	SYSTEM_CALL_TBL_ENTRY(sys_shmat),	/* 280 */
	SYSTEM_CALL_TBL_ENTRY(sys_shmdt),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 285 */
	SYSTEM_CALL_TBL_ENTRY(sys_accept4),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),	/* 289 __NR_ioprio_set */
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 __NR_ioprio_get */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),/* 291 __NR_inotify_init */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
			/* 292 __NR_inotify_add_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
			/* 293 __NR_inotify_rm_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 295 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group),	/* 300 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 305 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 310 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 315 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 320 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 325 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 330 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 340 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_preadv),
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 370 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_prlimit64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 380 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 390 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_preadv2),
	SYSTEM_CALL_TBL_ENTRY(sys_pwritev2),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 400 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),

	/* free (unused) items */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 402 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 403 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 404 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 405 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 406 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 407 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 408 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 409 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 410 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 411 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 412 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 413 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 414 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 415 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 416 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 417 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 418 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 419 */

	/* protected specific system calls entries */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 420 __NR_newuselib */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 421 __NR_rt_sigaction_ex */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 422 __NR_get_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 423 __NR_free_mem */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 424 __NR_clean_descriptors */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /* 425 __NR_unuselib */

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 430 */
	/* 430 last System call */
};

/*
 * System call handlers for protected mode entry #8:
 */
const protected_system_call_func sys_call_table_entry8[NR_syscalls] = {
	PROT_SYSCALL_TBL_ENTRY(sys_restart_syscall),	/* 0 */
	PROT_SYSCALL_TBL_ENTRY(sys_exit),
	PROT_SYSCALL_TBL_ENTRY(sys_fork),
	PROT_SYSCALL_TBL_ENTRY(sys_read),
	PROT_SYSCALL_TBL_ENTRY(sys_write),
	PROT_SYSCALL_TBL_ENTRY(sys_open),	/* 5 */
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
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old break syscall holder */

	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat() */
	PROT_SYSCALL_TBL_ENTRY(sys_lseek),
	PROT_SYSCALL_TBL_ENTRY(sys_getpid),	/* 20 */
	PROT_SYSCALL_TBL_ENTRY(sys_mount),
	PROT_SYSCALL_TBL_ENTRY(sys_oldumount),
	PROT_SYSCALL_TBL_ENTRY(sys_setuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getuid),
	PROT_SYSCALL_TBL_ENTRY(sys_stime),	/* 25 */
	PROT_SYSCALL_TBL_ENTRY(sys_ptrace),
	PROT_SYSCALL_TBL_ENTRY(sys_alarm),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	PROT_SYSCALL_TBL_ENTRY(sys_pause),
	PROT_SYSCALL_TBL_ENTRY(sys_utime),	/* 30 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old stty syscall holder */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old gtty syscall holder */
	PROT_SYSCALL_TBL_ENTRY(sys_access),
	PROT_SYSCALL_TBL_ENTRY(sys_nice),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 35, old ftime syscall */
	PROT_SYSCALL_TBL_ENTRY(sys_sync),
	PROT_SYSCALL_TBL_ENTRY(sys_kill),
	PROT_SYSCALL_TBL_ENTRY(sys_rename),
	PROT_SYSCALL_TBL_ENTRY(sys_mkdir),
	PROT_SYSCALL_TBL_ENTRY(sys_rmdir),	/* 40 */
	PROT_SYSCALL_TBL_ENTRY(sys_dup),
	PROT_SYSCALL_TBL_ENTRY(sys_pipe),
	PROT_SYSCALL_TBL_ENTRY(sys_times),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old prof syscall holder */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* brk() unavailable in PM */
	PROT_SYSCALL_TBL_ENTRY(sys_setgid),	/* 46 */
	PROT_SYSCALL_TBL_ENTRY(sys_getgid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* signal() have to be        */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	PROT_SYSCALL_TBL_ENTRY(sys_geteuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getegid),	/* 50 */
	PROT_SYSCALL_TBL_ENTRY(sys_acct),
	PROT_SYSCALL_TBL_ENTRY(sys_umount),	/* recycled never used phys() */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old lock syscall holder */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_ioctl),

	PROT_SYSCALL_TBL_ENTRY(sys_fcntl),	/* 55 */ /* for 64 & 32 */

	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old mpx syscall holder */
	PROT_SYSCALL_TBL_ENTRY(sys_setpgid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old ulimit syscall holder */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* oldolduname */
	PROT_SYSCALL_TBL_ENTRY(sys_umask),	/* 60 */
	PROT_SYSCALL_TBL_ENTRY(sys_chroot),
	PROT_SYSCALL_TBL_ENTRY(sys_ustat),
	PROT_SYSCALL_TBL_ENTRY(sys_dup2),
	PROT_SYSCALL_TBL_ENTRY(sys_getppid),
	PROT_SYSCALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	PROT_SYSCALL_TBL_ENTRY(sys_setsid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* no sys_sigaction(), use    */
						/* sys_rt_sigaction() instead */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_sgetmask obsoleted */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_ssetmask obsoleted */
	PROT_SYSCALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	PROT_SYSCALL_TBL_ENTRY(sys_setregid),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_sigpending),
	PROT_SYSCALL_TBL_ENTRY(sys_sethostname),
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_old_getrlimit),
	PROT_SYSCALL_TBL_ENTRY(sys_getrusage),
	PROT_SYSCALL_TBL_ENTRY(sys_gettimeofday),
	PROT_SYSCALL_TBL_ENTRY(sys_settimeofday),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_getgroups),	/* 80 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_setgroups),
	PROT_SYSCALL_TBL_ENTRY(sys_select),
	PROT_SYSCALL_TBL_ENTRY(sys_symlink),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat() */
	PROT_SYSCALL_TBL_ENTRY(sys_readlink),	/* 85 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_olduselib), /* obsolete syscall */
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
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old profil syscall holder */
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
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	PROT_SYSCALL_TBL_ENTRY(sys_vhangup),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* old "idle" system call */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_wait4),
	PROT_SYSCALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	PROT_SYSCALL_TBL_ENTRY(sys_sysinfo),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_ipc),
	PROT_SYSCALL_TBL_ENTRY(sys_fsync),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_clone),	/* 120 */
	PROT_SYSCALL_TBL_ENTRY(sys_setdomainname),
	PROT_SYSCALL_TBL_ENTRY(sys_newuname),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_adjtimex),
	PROT_SYSCALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	PROT_SYSCALL_TBL_ENTRY(sys_sigprocmask),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_init_module),
	PROT_SYSCALL_TBL_ENTRY(sys_delete_module),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	PROT_SYSCALL_TBL_ENTRY(sys_quotactl),
	PROT_SYSCALL_TBL_ENTRY(sys_getpgid),
	PROT_SYSCALL_TBL_ENTRY(sys_fchdir),
	PROT_SYSCALL_TBL_ENTRY(sys_bdflush),
	PROT_SYSCALL_TBL_ENTRY(sys_sysfs),	/* 135 - obsolete */
	PROT_SYSCALL_TBL_ENTRY(sys_personality),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* for afs_syscall */
	PROT_SYSCALL_TBL_ENTRY(sys_setfsuid),
	PROT_SYSCALL_TBL_ENTRY(sys_setfsgid),
	PROT_SYSCALL_TBL_ENTRY(sys_llseek),	/* 140 */
	PROT_SYSCALL_TBL_ENTRY(sys_getdents),
	PROT_SYSCALL_TBL_ENTRY(sys_select),
	PROT_SYSCALL_TBL_ENTRY(sys_flock),
	PROT_SYSCALL_TBL_ENTRY(sys_msync),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_readv),	/* 145 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_writev),
	PROT_SYSCALL_TBL_ENTRY(sys_getsid),
	PROT_SYSCALL_TBL_ENTRY(sys_fdatasync),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_sysctl),
	PROT_SYSCALL_TBL_ENTRY(sys_mlock),	/* 150 */
	PROT_SYSCALL_TBL_ENTRY(sys_munlock),
	PROT_SYSCALL_TBL_ENTRY(sys_mlockall),
	PROT_SYSCALL_TBL_ENTRY(sys_munlockall),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setparam),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getparam),   /* 155 */
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setscheduler),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getscheduler),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_yield),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_get_priority_max),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_get_priority_min),  /* 160 */
	PROT_SYSCALL_TBL_ENTRY(sys_sched_rr_get_interval),
	PROT_SYSCALL_TBL_ENTRY(sys_nanosleep),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mremap),
	PROT_SYSCALL_TBL_ENTRY(sys_setresuid),
	PROT_SYSCALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_poll),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 169 sys_nfsservctl	*/
	PROT_SYSCALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	PROT_SYSCALL_TBL_ENTRY(sys_getresgid),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_prctl),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 173 sys_rt_sigreturn	*/
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigaction),
	PROT_SYSCALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	PROT_SYSCALL_TBL_ENTRY(sys_rt_sigpending),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigtimedwait),
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
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 188 sys_getpmsg */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 189 sys_putpmsg */
	PROT_SYSCALL_TBL_ENTRY(sys_vfork),	/* 190 */
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_getrlimit),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mmap2),

	/* Entries 193-194 are for BITS_PER_LONG == 32; and this is 64 bit OS */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall), /* 193 sys_truncate64	*/
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 194 sys_ftruncate64	*/

	PROT_SYSCALL_TBL_ENTRY(sys_stat64), /* 195 */
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

	PROT_SYSCALL_TBL_ENTRY(protected_sys_pidfd_send_signal), /* 205 */
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
	PROT_SYSCALL_TBL_ENTRY(sys_mincore),
	PROT_SYSCALL_TBL_ENTRY(sys_madvise),
	PROT_SYSCALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	PROT_SYSCALL_TBL_ENTRY(sys_fcntl),	/* 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs
						 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
	PROT_SYSCALL_TBL_ENTRY(sys_newfstatat),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/*sys_e2k_setjmp in traptable*/
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/*sys_e2k_longjmp in traptable*/
	PROT_SYSCALL_TBL_ENTRY(sys_e2k_syswork),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone_thread */
	PROT_SYSCALL_TBL_ENTRY(sys_e2k_longjmp2), /* 230 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
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
	PROT_SYSCALL_TBL_ENTRY(sys_el_posix), /* 255 */
	PROT_SYSCALL_TBL_ENTRY(sys_io_uring_setup),
	PROT_SYSCALL_TBL_ENTRY(sys_io_uring_enter),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_io_uring_register),
	PROT_SYSCALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	PROT_SYSCALL_TBL_ENTRY(sys_el_binary), /* 260 */
#else
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
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
	PROT_SYSCALL_TBL_ENTRY(sys_msgget),	/* 270 */
	PROT_SYSCALL_TBL_ENTRY(sys_msgctl),
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
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 285 */
	PROT_SYSCALL_TBL_ENTRY(sys_accept4),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_setattr),
	PROT_SYSCALL_TBL_ENTRY(sys_sched_getattr),
	PROT_SYSCALL_TBL_ENTRY(sys_ioprio_set),	/* 289 __NR_ioprio_set */
	PROT_SYSCALL_TBL_ENTRY(sys_ioprio_get),	/* 290 __NR_ioprio_get */
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_init),/* 291 __NR_inotify_init */
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_add_watch),
						/* 292 __NR_inotify_add_watch */
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_rm_watch),
						/* 293 __NR_inotify_rm_watch */
	PROT_SYSCALL_TBL_ENTRY(sys_io_setup),    /* 294 */
	PROT_SYSCALL_TBL_ENTRY(sys_io_destroy),
	PROT_SYSCALL_TBL_ENTRY(sys_io_getevents),
	PROT_SYSCALL_TBL_ENTRY(sys_io_submit),
	PROT_SYSCALL_TBL_ENTRY(sys_io_cancel),
	PROT_SYSCALL_TBL_ENTRY(sys_fadvise64),
	PROT_SYSCALL_TBL_ENTRY(sys_exit_group), /* 300 */
	PROT_SYSCALL_TBL_ENTRY(sys_lookup_dcookie),
	PROT_SYSCALL_TBL_ENTRY(sys_epoll_create),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_ctl),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_wait),
	PROT_SYSCALL_TBL_ENTRY(sys_remap_file_pages),
	PROT_SYSCALL_TBL_ENTRY(sys_statfs64),
	PROT_SYSCALL_TBL_ENTRY(sys_fstatfs64),
	PROT_SYSCALL_TBL_ENTRY(sys_tgkill),
	PROT_SYSCALL_TBL_ENTRY(sys_utimes),
	PROT_SYSCALL_TBL_ENTRY(sys_fadvise64_64), /* 310 */

	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */
					/* The system call isn't implemented
					 * in the Linux 2.6.14 kernel
					 */
	PROT_SYSCALL_TBL_ENTRY(sys_mbind),
	PROT_SYSCALL_TBL_ENTRY(sys_get_mempolicy),
	PROT_SYSCALL_TBL_ENTRY(sys_set_mempolicy),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_open),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_unlink),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_timedsend),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_timedreceive),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_mq_notify),
	PROT_SYSCALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_kexec_load),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_waitid),
	PROT_SYSCALL_TBL_ENTRY(sys_add_key),
	PROT_SYSCALL_TBL_ENTRY(sys_request_key),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_keyctl),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* sys_mcst_rt */
	PROT_SYSCALL_TBL_ENTRY(sys_getcpu),
	PROT_SYSCALL_TBL_ENTRY(sys_move_pages),
	PROT_SYSCALL_TBL_ENTRY(sys_splice),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_vmsplice),	/* 330 */
	PROT_SYSCALL_TBL_ENTRY(sys_tee),
	PROT_SYSCALL_TBL_ENTRY(sys_migrate_pages),
	PROT_SYSCALL_TBL_ENTRY(sys_utimensat),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_tgsigqueueinfo),
	PROT_SYSCALL_TBL_ENTRY(sys_openat),
	PROT_SYSCALL_TBL_ENTRY(sys_mkdirat),
	PROT_SYSCALL_TBL_ENTRY(sys_mknodat),
	PROT_SYSCALL_TBL_ENTRY(sys_fchownat),
	PROT_SYSCALL_TBL_ENTRY(sys_unlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_renameat),	/* 340 */
	PROT_SYSCALL_TBL_ENTRY(sys_linkat),
	PROT_SYSCALL_TBL_ENTRY(sys_symlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_readlinkat),
	PROT_SYSCALL_TBL_ENTRY(sys_fchmodat),
	PROT_SYSCALL_TBL_ENTRY(sys_faccessat),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_epoll_pwait),
	PROT_SYSCALL_TBL_ENTRY(sys_signalfd4),
	PROT_SYSCALL_TBL_ENTRY(sys_eventfd2),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_recvmmsg),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
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
	PROT_SYSCALL_TBL_ENTRY(protected_sys_pwritev),
	PROT_SYSCALL_TBL_ENTRY(sys_fallocate),
	PROT_SYSCALL_TBL_ENTRY(sys_sync_file_range),
	PROT_SYSCALL_TBL_ENTRY(sys_dup3),
	PROT_SYSCALL_TBL_ENTRY(sys_inotify_init1),
	PROT_SYSCALL_TBL_ENTRY(sys_epoll_create1),/* 360 */
	PROT_SYSCALL_TBL_ENTRY(sys_fstatat64),
	PROT_SYSCALL_TBL_ENTRY(sys_futimesat),
	PROT_SYSCALL_TBL_ENTRY(sys_perf_event_open),
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
	PROT_SYSCALL_TBL_ENTRY(e2k_sys_prlimit64),
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
	PROT_SYSCALL_TBL_ENTRY(sys_getrandom),
	PROT_SYSCALL_TBL_ENTRY(sys_memfd_create),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_bpf),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_execveat),
	PROT_SYSCALL_TBL_ENTRY(sys_userfaultfd),
	PROT_SYSCALL_TBL_ENTRY(sys_membarrier),		/* 390 */
	PROT_SYSCALL_TBL_ENTRY(sys_mlock2),
	/* added in linux-4.9 */
	PROT_SYSCALL_TBL_ENTRY(sys_seccomp),
	PROT_SYSCALL_TBL_ENTRY(sys_shutdown),
	PROT_SYSCALL_TBL_ENTRY(sys_copy_file_range),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_preadv2),
	PROT_SYSCALL_TBL_ENTRY(protected_sys_pwritev2),

	/* free (unused) items */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),

	PROT_SYSCALL_TBL_ENTRY(sys_name_to_handle_at),	/* 400 */
	PROT_SYSCALL_TBL_ENTRY(sys_open_by_handle_at),	/* 401 */
	PROT_SYSCALL_TBL_ENTRY(sys_statx),		/* 402 */
	/* added for compatibility with x86_64 */
	PROT_SYSCALL_TBL_ENTRY(sys_socket),		/* 403 */
	PROT_SYSCALL_TBL_ENTRY(sys_connect),		/* 404 */
	PROT_SYSCALL_TBL_ENTRY(sys_accept),		/* 405 */
	PROT_SYSCALL_TBL_ENTRY(sys_sendto),		/* 406 */
	PROT_SYSCALL_TBL_ENTRY(sys_recvfrom),		/* 407 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_sendmsg),	/* 408 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_recvmsg),	/* 409 */
	PROT_SYSCALL_TBL_ENTRY(sys_bind),		/* 410 */
	PROT_SYSCALL_TBL_ENTRY(sys_listen),		/* 411 */
	PROT_SYSCALL_TBL_ENTRY(sys_getsockname),	/* 412 */
	PROT_SYSCALL_TBL_ENTRY(sys_getpeername),	/* 413 */
	PROT_SYSCALL_TBL_ENTRY(sys_socketpair),		/* 414 */
	PROT_SYSCALL_TBL_ENTRY(sys_setsockopt),		/* 415 */
	PROT_SYSCALL_TBL_ENTRY(sys_getsockopt),		/* 416 */

	/* free (unused) items */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 417 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 418 */

	/* protected specific system calls entries */
	PROT_SYSCALL_TBL_ENTRY(sys_arch_prctl),	/* 419 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_uselib), /* 420 __NR_newuselib */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_rt_sigaction_ex), /* 421 */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 422 __NR_get_mem */
	PROT_SYSCALL_TBL_ENTRY(sys_ni_syscall),	/* 423 __NR_free_mem */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_clean_descriptors), /* 424 */
	PROT_SYSCALL_TBL_ENTRY(protected_sys_unuselib), /* 425 */

	PROT_SYSCALL_TBL_ENTRY(sys_clone3),
	PROT_SYSCALL_TBL_ENTRY(sys_fsopen),
	PROT_SYSCALL_TBL_ENTRY(sys_fsconfig),
	PROT_SYSCALL_TBL_ENTRY(sys_fsmount),
	PROT_SYSCALL_TBL_ENTRY(sys_fspick),	/* 430 */

	/* 430 last System call */
}; /* sys_call_table_entry8 */

/*
 * Following is table of masks for pre-processing system call parameters
 *                             in the function ttable_entry*_C (ttable.c).
 * Format:
 *         <mask>, / *   syscall    #     <legend>   * / size1,..,size6
 * NB> Mask is hexadecimal expression of the bitmask binary value.
 * NB> Bits in the bitmask (four bits per argument) get coded right to left
 *					 starting with the bit #4 so that:
 *     - bit  #0    is SIZE_ADJUSTMENT bit (see below);
 *     - bits #1-3  unused for the moment;
 *     - bits #4-7  define type of system call argument #1;
 *     - bits #8-11 define type of system call argument #2;
 *     - bits #12-15 define type of system call argument #3;
 *                                 and so forth thru arg #6;
 *     - bits #28-32 - unused for the moment;
 *     - arg type codes (see the legend below) are:
 *		0(L) / 1(P) / 2(?) / 3(S) / 4(I) / 5(F) / f(X);
 * NB> Legend describes type of signal call arguments; left-to-right;
 *                                         starting with argument #1:
 *     'L' - is for 'long' - this argument gets passed as-is
 *                                to system call handler function;
 *     'P' - is for 'pointer' - this argument would be pre-processed in
 *              ttable_entry8_C to convert 'long' pointer descriptor used in
 *              the protected mode into the 'short' one used by kernel;
 *     '?' - may be either 'pointer' or 'long' depending on other arguments;
 *     'S' - is for string descriptor;
 *     'i' - is for 'int';
 *     'F' - pointer to function (function label);
 *     'X' - agrument doesn't exist.
 *     For example: LSLP legend is coded a system call like:
 *                               syscall( long, <string>, long, <pointer> ).
 * NB> Size(i) specifies minimum required size for syscall argument (i).
 * NB> Negative size means the actual value to be taken from the corresponding
 *     syscall argument. For example, size2 value '-3' means the minimum size
 *     for syscall argument #2 is provided thru argument #3 of the system call.
 *     If the actual value appears greater that the size of the corresponding
 *                  descriptor argument, and SIZE_ADJUSTMENT bit is set to'1',
 *                  then the actual size is set to the size of the descriptor.
 */
const struct syscall_attrs sys_protcall_args[NR_syscalls] = {
	{ 0x0,		/*	restart_syscall	0	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	exit	1		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	fork	2		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0141,	/*	read	3		iPL	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xfff0141,	/*	write	4		iPL	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xfff4430,	/*	open	5		Sii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	close	6		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	waitpid	7		iPi	*/
					0, 4, 0, 0, 0, 0 },
	{ 0xffff430,	/*	creat	8		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff330,	/*	link	9		SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	unlink	10		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1130,	/*	execve	11		SPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	chdir	12		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	time	13		PX	*/
					8, 0, 0, 0, 0, 0 },
	{ 0xfff0430,	/*	mknod	14		SiL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	chmod	15		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0030,	/*	lchown	16		SLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	break	17		XX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/*	oldstat	18		SP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4040,	/*	lseek	19		iLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getpid	20		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf103330,	/*	mount	21		SSSLP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	umount	22		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setuid	23		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getuid	24		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	stime	25		PX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff11000,	/*	ptrace 26		LLPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	alarm	27		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff100,	/*	oldfstat 28		LP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	pause	29		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/*	utime	30		SP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0x0,		/*	stty	31			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	gtty	32			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	access	33		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	nice	34		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	ftime	35		PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	sync	36		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	kill	37		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff330,	/*	rename	38		SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	mkdir	39		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	rmdir	40		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	dup	41		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	pipe	42		PX	*/
					8, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	times	43		PX	*/
					32, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	prof	44			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	brk	45		?X	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setgid	46		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getgid	47		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff100,	/*	signal	48		LP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	geteuid	49		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getegid	50		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	acct	51		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	umount2	52		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	lock	53			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff2040,	/*	ioctl	54		iL?	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff2440,	/*	fcntl	55		ii?	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	mpx	56			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setpgid	57		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff000,	/*	ulimit	58		LL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	oldolduname 59		PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	umask	60		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	chroot	61		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	ustat	62		iP	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xffff440,	/*	dup2	63		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getppid	64		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getpgrp	65		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	setsid	66		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1100,	/*	sigaction 67		LPP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	sgetmask	68	XX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff00,	/*	ssetmask	69	LX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setreuid	70	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setregid	71	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	sigsuspend	72	PX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	sigpending	73	PX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	sethostname	74	Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	setrlimit	75	iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xffff140,	/*	getrlimit	76	iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xffff140,	/*	getrusage	77	iP	*/
					0, 144, 0, 0, 0, 0 },
	{ 0xffff110,	/*	gettimeofday	78	PP	*/
					16, 8, 0, 0, 0, 0 },
	{ 0xffff110,	/*	settimeofday	79	PP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	getgroups	80	iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	setgroups	81	iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf111140,	/*	select	82		iPPPP	*/
					0, 128, 128, 128, 16, 0 },
	{ 0xffff330,	/*	symlink	83		SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	oldlstat 84			ni_syscall */
					0, 88, 0, 0, 0, 0 },
	{ 0xfff4131,	/*	readlink 85		SPi	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xffff130,	/*	uselib	86		SP	*/
					0, 96, 0, 0, 0, 0 },
	{ 0xffff430,	/*	swapon	87		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14440,	/*	reboot	88		iiiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	readdir	89		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0000020,	/*	mmap	90		?LLLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff010,	/*	munmap	91		PL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff030,	/*	truncate 92		SL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff040,	/*	ftruncate 93		iL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	fchmod	94		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	fchown	95		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	getpriority 96		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	setpriority	97	iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff00010,	/*	profil	98		PLLL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/*	statfs	99		SP	*/
					0, 120, 0, 0, 0, 0 },
	{ 0xffff140,	/*	fstatfs	100		iP	*/
					0, 120, 0, 0, 0, 0 },
	{ 0xfff4000,	/*	ioperm	101		LLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	socketcall      102	iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4141,	/*	syslog	103		iPi	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	setitimer	104	iPP	*/
					0, 32, 32, 0, 0, 0 },
	{ 0xffff140,	/*	getitimer	105	iP	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xffff130,	/*	stat	106		SP	*/
					0, 112, 0, 0, 0, 0 },
	{ 0xffff130,	/*	lstat	107		SP	*/
					0, 112, 0, 0, 0, 0 },
	{ 0xffff140,	/*	fstat	108		iP	*/
					0, 112, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	olduname 109		PX	*/
					325, 0, 0, 0, 0, 0 },
	{ 0xfffff00,	/*	iopl	110		LX	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	vhangup	111		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	idle	112			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	vm86old	113			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xff14140,	/*	wait4	114		iPiP	*/
					0, 4, 0, 144, 0, 0 },
	{ 0xfffff30,	/*	swapoff	115		SX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	sysinfo	116		PX	*/
					112, 0, 0, 0, 0, 0 },
	{ 0x0120440,	/*	ipc	117		iiL?PL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	fsync	118		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	sigreturn 119			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xf211100,	/*	clone	120		LPPP?	*/
					0, 0, 0, 0, 4, 0 },
	{ 0xffff411,	/*	setdomainname	121	Pi	*/
					-2, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	uname	122		PX	*/
					390, 0, 0, 0, 0, 0 },
	{ 0xfff0100,	/*	modify_ldt	123	LPL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	adjtimex	124	PX	*/
					216, 0, 0, 0, 0, 0 },
	{ 0xfff0011,	/*	mprotect	125	PLL	*/
					-2, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	sigprocmask	126	iPP	*/
					0, 8, 8, 0, 0, 0 },
	{ 0xffff030,	/*	create_module	127	SL	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff3010,	/*	init_module	128	PLS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	delete_module	129	Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	get_kernel_syms 130		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xff14340,	/*	quotactl	131	iSiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	getpgid	132		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	fchdir	133		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff040,	/*	bdflush	134		iL	[Obsolete] */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1240,	/*	sysfs	135		i?P	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	personality	136	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	afs_syscall 137			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setfsuid	138	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setfsgid	139	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf410040,	/*	_llseek	140		iLLPi	*/
					0, 0, 0, 8, 0, 0 },
	{ 0xfff4141,	/*	getdents	141	iPi	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xf111140,	/*	_newselect	142	iPPPP	*/
					0, 128, 128, 128, 16, 0 },
	{ 0xffff440,	/*	flock	143		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4010,	/*	msync	144		PLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0100,	/*	readv	145		LPL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xfff0100,	/*	writev	146		LPL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	getsid	147		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	fdatasync 148		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	_sysctl	149		PX	*/
					128, 0, 0, 0, 0, 0 },
	{ 0xffff020,	/*	mlock	150		?L	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff020,	/*	munlock	151		?L	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	mlockall 152		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	munlockall 153		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/* sched_setparam 154		iP	*/
					0, 4, 0, 0, 0, 0 },
	{ 0xffff140,	/* sched_getparam 155		iP	*/
					0, 4, 0, 0, 0, 0 },
	{ 0xfff1440,	/* sched_setscheduler 156	iiP	*/
					0, 0, 4, 0, 0, 0 },
	{ 0xfffff40,	/* sched_getscheduler 157	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/* sched_yield	158		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* sched_get_priority_max 159	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* sched_get_priority_min 160	iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/* sched_rr_get_interval 161	iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xffff110,	/*	nanosleep 162		PP	*/
					16, 16, 0, 0, 0, 0 },
	{ 0xf200010,	/*	mremap	163		PLLL?	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	setresuid 164		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1110,	/*	getresuid 165		PPP	*/
					4, 4, 4, 0, 0, 0 },
	{ 0x0,		/*	vm86	166			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xf101010,	/* query_module	167		PLPLP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4410,	/*	poll	168		Pii	*/
					8, 0, 0, 0, 0, 0 },
	{ 0xfff1100,	/*	nfsservctl	169	LPP	ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	setresgid	170	iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1110,	/*	getresgid	171	PPP	*/
					4, 4, 4, 0, 0, 0 },
	{ 0xf022240,	/*	prctl	172		i???L	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	rt_sigreturn 173		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xff01140,	/* rt_sigaction	174		iPPL	*/
					0, 32, 32, 0, 0, 0 },
	{ 0xff01140,	/* rt_sigprocmask 175		iPPL	*/
					0, 8, 8, 0, 0, 0 },
	{ 0xffff010,	/* rt_sigpending 176		PL	*/
					-2, 0, 0, 0, 0, 0 },
	{ 0xff01110,	/* rt_sigtimedwait 177		PPPL	*/
					8, 128, 16, 0, 0, 0 },
	{ 0xfff1440,	/* rt_sigqueueinfo 178		iiP	*/
					0, 0, 128, 0, 0, 0 },
	{ 0xffff010,	/* rt_sigsuspend 179		PL	*/
					-2, 0, 0, 0, 0, 0 },
	{ 0xff00141,	/*	pread	180		iPLL	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xff00141,	/*	pwrite	181		iPLL	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xfff4430,	/*	chown	182		Sii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff011,	/*	getcwd	183		PL	*/
					-2, 0, 0, 0, 0, 0 },
	{ 0xffff110,	/*	capget	184		PP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff110,	/*	capset	185		PP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff110,	/*	sigaltstack	186	PP	*/
					32, 32, 0, 0, 0, 0 },
	{ 0xff01440,	/*	sendfile	187	iiPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	getpmsg	188			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	putpmsg	189			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	vfork	190		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	ugetrlimit	191	iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0x0444020,	/*	mmap2	192		?LiiiL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	truncate64 193			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	ftruncate64 194			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/*	stat64	195		SP	*/
					0, 88, 0, 0, 0, 0 },
	{ 0xffff130,	/*	lstat64	196		SP	*/
					0, 88, 0, 0, 0, 0 },
	{ 0xffff100,	/*	fstat64	197		LP	*/
					0, 88, 0, 0, 0, 0 },
	{ 0xfff4430,	/*	lchown32	198	Sii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getuid32	199	XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getgid32	200	XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	geteuid32	201	XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	getegid32	202	XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setreuid32	203	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setregid32	204	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41440,	/* pidfd_send_signal	205	iiPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	pidfd_open	206	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	fchown32	207	iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	setresuid32	208	iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1110,	/*	getresuid32	209	PPP	*/
					4, 4, 4, 0, 0, 0 },
	{ 0xfff4440,	/*	setresgid32	210	iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1110,	/*	getresgid32	211	PPP	*/
					4, 4, 4, 0, 0, 0 },
	{ 0xfff4430,	/*	chown32	212		Sii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setuid32 213		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setgid32 214		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setfsuid32 215		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	setfsgid32 216		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff330,	/*	pivot_root 217		SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1010,	/*	mincore	218		PLP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4010,	/*	madvise	219		PLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4141,	/*	getdents64 220		iPi	*/
					0, -3, 0, 0, 0, 0 },
	{ 0xfff2440,	/*	fcntl64	221		ii?	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	core	222			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	macctl	223		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41340,	/*	newfstatat 224		iSPi	*/
					0, 0, 88, 0, 0, 0 },
	{ 0x0,		/*	emergency 225			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	e2k_sigsetjmp 226		ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	e2k_longjmp 227			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xf000000,	/*	e2k_syswork 228		LLLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	clone2	229			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff010,	/*	e2k_longjmp2	230	PL	*/
					64, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	soft_debug 231			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xf401330,	/*	setxattr	232	SSPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf401330,	/*	lsetxattr	233	SSPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf401340,	/*	fsetxattr	234	iSPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff01330,	/*	getxattr	235	SSPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff01330,	/*	lgetxattr	236	SSPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff01340,	/*	fgetxattr	237	iSPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0330,	/*	listxattr	238	SSL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0330,	/*	llistxattr	239	SSL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0340,	/*	flistxattr	240	iSL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff330,	/*	removexattr	241	SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff330,	/*	lremovexattr	242	SS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff340,	/*	fremovexattr	243	iS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/*	gettid	244		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0040,	/*	readahead	245	iLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	tkill	246		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff01440,	/*	sendfile64	247	iiPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x4224410,	/*	futex	248		Pii??i	*/
					4, 0, 0, 16, 4, 0 },
	{ 0xfff1440,	/*	sched_setaffinity 249	iiP */
					0, 0, -2, 0, 0, 0 },
	{ 0xfff1440,	/*	sched_getaffinity 250	iiP */
					0, 0, -2, 0, 0, 0 },
	{ 0xffff410,	/*	pipe2	251		Pi	*/
					8, 0, 0, 0, 0, 0 },
	{ 0xff00010,	/*	set_backtrace 252	PLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff00010,	/*	get_backtrace 253	PLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf101100,	/*	access_hw_stacks 254	LPPLP	*/
					0, 8, -4, 0, 8, 0 },
	{ 0xff22240,	/*	el_posix	255	i???	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	io_uring_setup 256	iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0144440,	/*	io_uring_enter 257	iiiiPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41440,	/*	io_uring_register 258	iiPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	set_tid_address	259	PX	*/
					4, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	el_binary	260	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	timer_create	261	iPP	*/
					0, 80, 4, 0, 0, 0 },
	{ 0xff11440,	/* timer_settime 262		iiPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/* timer_gettime 263		iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* timer_getoverrun 264		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* timer_delete	265		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/* clock_settime 266		iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xffff140,	/* clock_gettime 267		iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xffff140,	/* clock_getres	268		iP	*/
					0, 16, 0, 0, 0, 0 },
	{ 0xff11440,	/* clock_nanosleep 269		iiPP	*/
					0, 0, 16, 16, 0, 0 },
	{ 0xffff440,	/*	msgget	270		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1440,	/*	msgctl	271		iiP	*/
					0, 0, 32, 0, 0, 0 },
	{ 0xf400140,	/*	msgrcv	272		iPLLi	*/
					0, 8, 0, 0, 0, 0 },
	{ 0xff40140,	/*	msgsnd	273		iPLi	*/
					0, 8, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	semget	274		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff24440,	/*	semctl	275		iii?	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14140,	/* semtimedop	276		iPiP	*/
					0, 6, 0, 16, 0, 0 },
	{ 0xfff0140,	/*	semop	277		iPL	*/
					0, 6, 0, 0, 0, 0 },
	{ 0xfff4040,	/*	shmget	278		iLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1440,	/*	shmctl	279		iiP	*/
					0, 0, 40, 0, 0, 0 },
	{ 0xfff4240,	/*	shmat	280		i?i	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	shmdt	281		P	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	open_tree 282		iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf434340,	/*	move_mount 283		iSiSi */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	284	*/ 0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	285	*/ 0, 0, 0, 0, 0, 0 },

	{ 0xff41140,	/*	accept4	286		iPPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/* sched_setattr 287		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff44140,	/* sched_getattr 288		iPii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/* ioprio_set	289		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/* ioprio_get	290		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffffff0,	/* inotify_init	291		XX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/* inotify_add_watch 292	iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/* inotify_rm_watch 293		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	io_setup 294		iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff00,	/*	io_destroy 295		LX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf110000,	/*	io_getevents 296	LLLPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1000,	/*	io_submit 297		LLP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1100,	/*	io_cancel 298		LPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff40040,	/*	fadvise64 299		iLLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* exit_group	300		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0100,	/* lookup_dcookie 301		LPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* epoll_create	302		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14440,	/*	epoll_ctl 303		iiiP */
					0, 0, 0, 0, 0, 0 },
	{ 0xff44140,	/* epoll_wait	304		iPii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf000010,	/* remap_file_pages	305	PLLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1030,	/*	statfs64	306	SLP	*/
					0, 120, 0, 0, 0, 0 },
	{ 0xfff1040,	/*	fstatfs64	307	iLP	*/
					0, 120, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	tgkill	308		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/*	utimes	309		SP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff40040,	/*	fadvise64_64	310	iLLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	vserver	311			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x4010010,	/*	mbind	312		PLLPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf000110,	/*	get_mempolicy	313	PPLLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0140,	/*	set_mempolicy	314	iPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14430,	/*	mq_open	315		SiiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff30,	/*	mq_unlink  (__NR_mq_open+1)	SX    */
					0, 0, 0, 0, 0, 0 },
	{ 0xf140140,	/* mq_timedsend    (__NR_mq_open+2)	iPLiP */
					0, 0, 0, 0, 0, 0 },
	{ 0xf110140,	/* mq_timedreceive (__NR_mq_open+3)	iPLPP */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/*	mq_notify  (__NR_mq_open+4)	iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/* mq_getsetattr   (__NR_mq_open+5)	iPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff01000,	/*	kexec_load	321	LLPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf141440,	/*	waitid	322		iiPiP	*/
					0, 0, 128, 0, 144, 0 },
	{ 0xf401110,	/*	add_key	323		PPPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41110,	/* request_key	324		PPPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf222240,	/*	keyctl	325		i????	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	mcst_rt	326			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1110,	/*	getcpu	327		PPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x4111000,	/*	move_pages 328		LLPPPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x4014140,	/*	splice	329		iPiPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff40140,	/*	vmsplice 330		iPLi	*/
					0, 24, 0, 0, 0, 0 },
	{ 0xff40440,	/*	tee	331		iiLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff11040,	/* migrate_pages 332		iLPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41140,	/*	utimensat 333		iPPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14440,	/* rt_tgsigqueueinfo	334	iiiP	*/
					0, 0, 0, 128, 0, 0 },
	{ 0xff44340,	/*	openat	335		iSii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	mkdirat	336		iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff44340,	/*	mknodat	337		iSii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf444340,	/*	fchownat 338		iSiii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	unlinkat 339		iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff34340,	/*	renameat 340		iSiS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf434340,	/*	linkat	341		iSiSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff3430,	/*	symlinkat 342		SiS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41341,	/*	readlinkat 343		iSPi	*/
					0, 0, -4, 0, 0, 0 },
	{ 0xfff4340,	/*	fchmodat 344		iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	faccessat 345		iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0144140,	/*	epoll_pwait 346		iPiiPL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff40140,	/*	signalfd4 347		iPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	eventfd2 348		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf144140,	/*	recvmmsg 349		iPiiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	cnt_point 350			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/* timerfd_create 351		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff11440,	/* timerfd_settime 352		iiPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff140,	/* timerfd_gettime 353		iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf000100,	/*	preadv	354		LPLLL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xf000100,	/*	pwritev	355		LPLLL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xff00440,	/*	fallocate 356		iiLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff40040,	/* sync_file_range 357		iLLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	dup3	358		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* inotify_init1 359		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/* epoll_create1 360		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff41340,	/*	fstatat64 361		iSPi	*/
					0, 0, 88, 0, 0, 0 },
	{ 0xfff1340,	/*	futimesat 362		iSP	*/
					0, 0, 32, 0, 0, 0 },
	{ 0xf044410,	/* perf_event_open 363		PiiiL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff00,	/*	unshare	364		LX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/* get_robust_list 365		iPP	*/
					0, 16, 8, 0, 0, 0 },
	{ 0xffff010,	/* set_robust_list 366		PL	*/
					0x30, 0, 0, 0, 0, 0 },
	{ 0x1111140,	/*	pselect6 367		iPPPPP */
					0, 128, 128, 128, 16, 16 },
	{ 0xf011410,	/*	ppoll	368		PiPPL	*/
					8, 0, 16, 8, 0, 0 },
	{ 0xffff410,	/*	setcontext 369		Pi	*/
					332, 0, 0, 0, 0, 0 },
	{ 0xf410510,	/*	makecontext 370		PFLPi	*/
					332, 0, 0, 0, 0, 0 },
	{ 0xfff4110,	/*	swapcontext 371		PPi	*/
					332, 332, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	freecontext 372		PX	*/
					332, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	fanotify_init 373	ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf340440,	/* fanotify_mark 374		iiLiS	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff11440,	/*	prlimit64 375		iiPP	*/
					0, 0, 16, 16, 0, 0 },
	{ 0xffff140,	/*clock_adjtime	376		iP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	syncfs	377		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff44140,	/*	sendmmsg 378		iPii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	setns	379		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0010140,	/* process_vm_readv 380		iPLPLL	*/
					0, 32, 0, 32, 0, 0 },
	{ 0x0010140,	/* process_vm_writev 381	iPLPLL	*/
					0, 32, 0, 32, 0, 0 },
	{ 0xf004440,	/*	kcmp	382		iiiLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	finit_module 383	iSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf434340,	/*	renameat2 384		iSiSi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4010,	/*	getrandom 385		PLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff410,	/*	memfd_create 386	Pi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	bpf	387		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf411340,	/*	execveat 388		iSPPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff40,	/*	userfaultfd 389		iX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	membarrier 390		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4020,	/*	mlock2	391		?Li	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1440,	/*	seccomp	392		iiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	shutdown 393		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x4014140,	/* copy_file_range 394		iPiPLi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0000100,	/*	preadv2	395		LPLLLL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0x0000100,	/*	pwritev2 396		LPLLLL	*/
					0, 32, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	397	*/ 0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	398	*/ 0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	399	*/ 0, 0, 0, 0, 0, 0 },
	{ 0xf411340,	/* name_to_handle_at 400	iSPPi	*/
					0, 0, 8, 0, 0, 0 },
	{ 0xfff4140,	/* open_by_handle_at 401	iPi	*/
					0, 8, 0, 0, 0, 0 },
	{ 0xf144340,	/*	statx	402		iSiiP	*/
					0, 0, 0, 0, 256, 0 },
	{ 0xfff4440,	/*	socket	403		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	connect	404		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	accept	405		iPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x4140140,	/*	sendto	406		iPLiPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x1140140,	/*	recvfrom 407		iPLiPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	sendmsg	408		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	recvmsg	409		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4140,	/*	bind	410		iPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff440,	/*	listen	411		ii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	getsockname 412		iPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff1140,	/*	getpeername	413	iPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xff14440,	/*	socketpair	414	iiiP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf414440,	/*	setsockopt	415	iiiPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf114440,	/*	getsockopt	416	iiiPP	*/
					0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	417	*/ 0, 0, 0, 0, 0, 0 },
	{ 0x0,	/*	reserved	418	*/ 0, 0, 0, 0, 0, 0 },

	{ 0xf022240,	/*	arch_prctl 419		i???L	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff130,	/* newuselib	420		SP	*/
					0, 32, 0, 0, 0, 0 },
	{ 0xff01140,	/* rt_sigaction_ex 421		iPPL	*/
					0, 56, 56, 0, 0, 0 },
	{ 0x0,		/*	get_mem	422			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0x0,		/*	free_mem 423			ni_syscall */
					0, 0, 0, 0, 0, 0 },
	{ 0xfff0010,	/* clean_descriptors 424	PLL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfffff10,	/*	unuselib 425		PX	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff010,	/*	clone3	426		PL	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xffff430,	/*	fsopen	427		Si	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xf413440,	/*	fsconfig 428		iiSPi	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4440,	/*	fsmount	429		iii	*/
					0, 0, 0, 0, 0, 0 },
	{ 0xfff4340,	/*	fspick	430		iSi	*/
					0, 0, 0, 0, 0, 0 }
};

/*
 * System call name table:
 */
const char *sys_call_ID_to_name[NR_syscalls] = {
	"restart_syscall", /* 0 */
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
	"ni_syscall",	/* old break syscall holder */

	"ni_syscall",	/* old sys_stat() */
	"lseek",
	"getpid",	/* 20 */
	"mount",
	"oldumount",
	"setuid",
	"getuid",
	"stime",	/* 25 */
	"ptrace",
	"alarm",
	"ni_syscall",	/* old sys_fstat() */
	"pause",
	"utime",	/* 30 */
	"ni_syscall",	/* old stty syscall holder */
	"ni_syscall",	/* old gtty syscall holder */
	"access",
	"nice",
	"ni_syscall",	/* 35, old ftime syscall */
	"sync",
	"kill",
	"rename",
	"mkdir",
	"rmdir",	/* 40 */
	"dup",
	"pipe",
	"times",
	"ni_syscall",	/* old prof syscall holder */
	"brk",		/* 45 */
	"setgid",
	"getgid",
	"ni_syscall",	/* signal() have to be emulated by rt_sigaction() */
	"geteuid",
	"getegid",	/* 50 */
	"acct",
	"umount",	/* recycled never used phys() */
	"ni_syscall",	/* old lock syscall holder */
	"ioctl",

	"fcntl",	/* 55 */

	"ni_syscall",	/* old mpx syscall holder */
	"setpgid",
	"ni_syscall",	/* old ulimit syscall holder */
	"ni_syscall",	/* oldolduname */
	"umask",	/* 60 */
	"chroot",
	"ustat",
	"dup2",
	"getppid",
	"getpgrp",	/* 65 */
	"setsid",
	"ni_syscall",	/* no sys_sigaction() */
	"sgetmask",
	"ssetmask",
	"setreuid",	/* 70 */
	"setregid",
	"ni_syscall",
	"sigpending",
	"sethostname",
	"setrlimit",	/* 75 */
	"old_getrlimit",
	"getrusage",
	"gettimeofday",
	"settimeofday",
	"getgroups",	/* 80 */
	"setgroups",
	"select",
	"symlink",
	"ni_syscall",	/* old sys_lstat() */
	"readlink",	/* 85 */
	"olduselib", /* obsolete syscall */
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
	"ni_syscall",	/* old profil syscall holder */
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
	"ni_syscall",	/* 110 */
	"vhangup",
	"ni_syscall",	/* old "idle" system call */
	"ni_syscall",
	"wait4",
	"swapoff",	/* 115 */
	"sysinfo",
	"ipc",
	"fsync",
	"ni_syscall",
	"clone",	/* 120 */
	"setdomainname",
	"newuname",
	"ni_syscall",
	"adjtimex",
	"mprotect",	/* 125 */
	"sigprocmask",
	"ni_syscall",
	"init_module",
	"delete_module",
	"ni_syscall",	/* 130 */
	"quotactl",
	"getpgid",
	"fchdir",
	"bdflush",
	"sysfs",	/* 135 - obsolete */
	"personality",
	"ni_syscall",	/* for afs_syscall */
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
	"sysctl",
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
	"ni_syscall",
	"ni_syscall",
	"poll",
	"ni_syscall",	/* 169 sys_nfsservctl	*/
	"setresgid",	/* 170 */
	"getresgid",
	"prctl",
	"ni_syscall",	/* 173 sys_rt_sigreturn	*/
	"rt_sigaction",
	"rt_sigprocmask",	/* 175 */
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"pread64",		/* 180 */
	"pwrite64",
	"chown",
	"getcwd",
	"capget",
	"capset",	/* 185 */
	"sigaltstack",
	"sendfile64",
	"ni_syscall",	/* 188 sys_getpmsg */
	"ni_syscall",	/* 189 sys_putpmsg */
	"vfork",	/* 190 */
	"getrlimit",
	"mmap2",

	/* Entries 193-194 are for BITS_PER_LONG == 32; and this is 64 bit OS */
	"ni_syscall", /* 193 sys_truncate64	*/
	"ni_syscall",	/* 194 sys_ftruncate64	*/

	"stat64",	/* 195 */
	"lstat64",
	"fstat64",

	"lchown",
	"getuid",
	"getgid",	/* 200 */
	"geteuid",
	"getegid",
	"setreuid",
	"setregid",
	"pidfd_send_signal",	/* 205 */
	"pidfd_open",
	"fchown",
	"setresuid",
	"getresuid",
	"setresgid",	/* 210 */
	"getresgid",
	"chown",
	"setuid",
	"setgid",
	"setfsuid",	/* 215 */
	"setfsgid",
	"pivot_root",
	"mincore",
	"madvise",
	"getdents64",	/* 220 */
	"fcntl",	/* 221 */
	"ni_syscall",
	"ni_syscall",	/* 223 */
	"newfstatat",
	"ni_syscall",	/* 225 */
	"ni_syscall",	/*sys_e2k_setjmp in traptable*/
	"ni_syscall",	/*sys_e2k_longjmp in traptable*/
	"e2k_syswork",
	"ni_syscall",	/* sys_clone_thread */
	"e2k_longjmp2", /* 230 */
	"ni_syscall",
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
#if defined CONFIG_FUTEX
	"futex",
#else
	"ni_syscall",
#endif
	"sched_setaffinity",
	"sched_getaffinity",	/* 250 */
	"pipe2",
	"set_backtrace",
	"get_backtrace",
	"access_hw_stacks",
	"el_posix",	/* 255 */
	"io_uring_setup",
	"io_uring_enter",
	"io_uring_register",
	"set_tid_address",
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	"el_binary", /* 260 */
#else
	"ni_syscall",	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
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

	"ni_syscall",	/*  __NR_vserver - isn't implemented
			 * in the Linux 2.6.14 kernel
			 */
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
	"ni_syscall",	/* sys_mcst_rt */
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
	"ni_syscall",	/* 350 */
#ifdef CONFIG_TIMERFD
	"timerfd_create",
	"timerfd_settime",
	"timerfd_gettime",
#else
	"ni_syscall",
	"ni_syscall",
	"ni_syscall",
#endif
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
	"ni_syscall",		/* 397 */
	"ni_syscall",		/* 398 */
	"ni_syscall",		/* 399 */

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
	"ni_syscall",	/* 417 */
	"ni_syscall",	/* 418 */

	/* protected specific system calls entries */
	"arch_prctl",	/* 419 */
	"uselib",	/* 420 __NR_newuselib */
	"rt_sigaction_ex", /* 421 */
	"ni_syscall",	/* 422 __NR_get_mem */
	"ni_syscall",	/* 423 __NR_free_mem */
	"clean_descriptors", /* 424 */
	"unuselib", /* 425 */

	"clone3",
	"fsopen",
	"fsconfig",
	"fsmount",
	"fspick",	/* 430 */
};


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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_execve),
	SYSTEM_CALL_TBL_ENTRY(sys_chdir),
	SYSTEM_CALL_TBL_ENTRY(sys_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mknod),
	SYSTEM_CALL_TBL_ENTRY(sys_chmod),	/* 15 */
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old break syscall holder */
	
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_stat() */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_lseek),
	SYSTEM_CALL_TBL_ENTRY(sys_getpid),	/* 20 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mount),
	SYSTEM_CALL_TBL_ENTRY(sys_oldumount),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_stime32),	/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	SYSTEM_CALL_TBL_ENTRY(sys_utime),/* 30 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old stty syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old gtty syscall holder */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old prof syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_brk),		/* 45 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* signal() have to be        */
						/* emulated by rt_sigaction() */
						/* on user level (GLIBC)      */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),	/* 50 */
	SYSTEM_CALL_TBL_ENTRY(sys_acct),
	SYSTEM_CALL_TBL_ENTRY(sys_umount),	/* recycled never used phys() */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old lock syscall holder */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ioctl),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),/* 55 */ /* for 64 & 32 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old mpx syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_setpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old ulimit syscall holder */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_umask),	/* 60 */
	SYSTEM_CALL_TBL_ENTRY(sys_chroot),
	SYSTEM_CALL_TBL_ENTRY(sys_ustat),
	SYSTEM_CALL_TBL_ENTRY(sys_dup2),
	SYSTEM_CALL_TBL_ENTRY(sys_getppid),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgrp),	/* 65 */
	SYSTEM_CALL_TBL_ENTRY(sys_setsid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* no sys_sigaction(), use    */
	SYSTEM_CALL_TBL_ENTRY(sys_sgetmask),	/* sys_rt_sigaction() instead */
	SYSTEM_CALL_TBL_ENTRY(sys_ssetmask),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),	/* 70 */
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigpending),
	SYSTEM_CALL_TBL_ENTRY(sys_sethostname),
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_setrlimit),	/* 75 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_getrusage),
	SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday),
	SYSTEM_CALL_TBL_ENTRY(sys_getgroups),	/* 80 */
	SYSTEM_CALL_TBL_ENTRY(sys_setgroups),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_symlink),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_lstat() */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old profil syscall holder */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs),	/* 100 */
	SYSTEM_CALL_TBL_ENTRY(sys_ioperm),
	SYSTEM_CALL_TBL_ENTRY(sys_socketcall),
	SYSTEM_CALL_TBL_ENTRY(sys_syslog),
	SYSTEM_CALL_TBL_ENTRY(sys_setitimer),
	SYSTEM_CALL_TBL_ENTRY(sys_getitimer),	/* 105 */
	
	SYSTEM_CALL_TBL_ENTRY(sys_newstat),     
	SYSTEM_CALL_TBL_ENTRY(sys_newlstat),   
	SYSTEM_CALL_TBL_ENTRY(sys_newfstat),   
	
	SYSTEM_CALL_TBL_ENTRY(sys_uname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 110 */
	SYSTEM_CALL_TBL_ENTRY(sys_vhangup),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old "idle" system call */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_wait4),
	SYSTEM_CALL_TBL_ENTRY(sys_swapoff),	/* 115 */
	SYSTEM_CALL_TBL_ENTRY(sys_sysinfo),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ipc),
	SYSTEM_CALL_TBL_ENTRY(sys_fsync),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_adjtimex_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mprotect),	/* 125 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigprocmask),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_init_module),
	SYSTEM_CALL_TBL_ENTRY(sys_delete_module),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 130 */
	SYSTEM_CALL_TBL_ENTRY(sys_quotactl),
	SYSTEM_CALL_TBL_ENTRY(sys_getpgid),
	SYSTEM_CALL_TBL_ENTRY(sys_fchdir),
	SYSTEM_CALL_TBL_ENTRY(sys_bdflush),
	SYSTEM_CALL_TBL_ENTRY(sys_sysfs),	/* 135 */
	SYSTEM_CALL_TBL_ENTRY(sys_personality),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* for afs_syscall */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_llseek),	/* 140 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents),
	SYSTEM_CALL_TBL_ENTRY(sys_select),
	SYSTEM_CALL_TBL_ENTRY(sys_flock),
	SYSTEM_CALL_TBL_ENTRY(sys_msync),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_readv),	/* 145 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_getsid),
	SYSTEM_CALL_TBL_ENTRY(sys_fdatasync),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sysctl),
	SYSTEM_CALL_TBL_ENTRY(sys_mlock),	/* 150 */
	SYSTEM_CALL_TBL_ENTRY(sys_munlock),
	SYSTEM_CALL_TBL_ENTRY(sys_mlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_munlockall),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setparam),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getparam),   /* 155 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_setscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_getscheduler),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_yield),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_max),
	SYSTEM_CALL_TBL_ENTRY(sys_sched_get_priority_min),  /* 160 */
	SYSTEM_CALL_TBL_ENTRY(sys_sched_rr_get_interval_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_nanosleep),
	SYSTEM_CALL_TBL_ENTRY(sys_mremap),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getresuid),	/* 165 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_poll),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* was sys_nfsservctl */
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
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile64),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64), 
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195 , in libc used in ptr32 mode */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_setjmp */
	SYSTEM_CALL_TBL_ENTRY(sys_deprecated),  /*sys_e2k_longjmp*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_clone_thread),
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_longjmp2), /* 230 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix),	/* 255 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 256 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_set),	/* 289 __NR_ioprio_set */
	SYSTEM_CALL_TBL_ENTRY(sys_ioprio_get),	/* 290 __NR_ioprio_get */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init),/* 291 __NR_inotify_init */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_add_watch),
						/* 292 __NR_inotify_add_watch */
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_rm_watch),
						/* 293 __NR_inotify_rm_watch */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_setup),    /* 294 */
	SYSTEM_CALL_TBL_ENTRY(sys_io_destroy),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_getevents_time32), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_submit),  
	SYSTEM_CALL_TBL_ENTRY(sys_io_cancel),  
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64),  
	SYSTEM_CALL_TBL_ENTRY(sys_exit_group), /* 300 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_ctl), 
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_wait), 
	SYSTEM_CALL_TBL_ENTRY(sys_remap_file_pages), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_statfs64), 
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fstatfs64), 
	SYSTEM_CALL_TBL_ENTRY(sys_tgkill), 
	SYSTEM_CALL_TBL_ENTRY(sys_utimes_time32), 
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64), /* 310 */
        
        SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */ 
                                          /*The system call isn't implemented in the Linux 2.6.14
                                             * kernel  */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend_time32),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive_time32),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
#ifdef CONFIG_KEYS_COMPAT
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_keyctl),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	/* This system call entry is deprecated so use
	 * sys_ni_syscall for all entries from now on. */
	[__NR_keyctl + 1 ... NR_syscalls - 1] = SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall)
};

