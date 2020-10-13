#include <linux/syscalls.h>
#include <linux/compat.h>

#include <asm/syscalls.h>
#include <asm/system.h>

#define	SYSTEM_CALL_DEFINE(sysname)	extern void * sysname (void)
#define	SYSTEM_CALL_TBL_ENTRY(sysname)	(system_call_func) sysname

#ifdef CONFIG_COMPAT
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(system_call_func) compat_##sysname
#else
# define COMPAT_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(system_call_func) sys_ni_syscall
#endif


/*
 * Real map of system calls.
 */

system_call_func sys_call_table[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 0 */
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
	
	SYSTEM_CALL_TBL_ENTRY(sys_newstat),     /* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newlstat),    /* in libc used in ptr64 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_newfstat),    /* in libc used in ptr64 mode */
	
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
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_clone),	/* 120 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigreturn() */
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
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_vfork),	/* 190 */
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
	
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
#ifdef CONFIG_MAC_
	SYSTEM_CALL_TBL_ENTRY(sys_macctl),	/* 223 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
#endif /* CONFIG_MAC_ */
	SYSTEM_CALL_TBL_ENTRY(sys_newfstatat),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_setjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_longjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone2 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 230 */
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
#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix), /* 255 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 255 */
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 256 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 Last valid system call*/
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
#ifdef CONFIG_RECOVERY
	SYSTEM_CALL_TBL_ENTRY(sys_cnt_point),	/* 350 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
#endif
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
	SYSTEM_CALL_TBL_ENTRY(sys_prlimit64),
	SYSTEM_CALL_TBL_ENTRY(sys_clock_adjtime),
	SYSTEM_CALL_TBL_ENTRY(sys_syncfs),
	SYSTEM_CALL_TBL_ENTRY(sys_sendmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_setns),
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_readv), /* 380 */
	SYSTEM_CALL_TBL_ENTRY(sys_process_vm_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_kcmp),
	SYSTEM_CALL_TBL_ENTRY(sys_finit_module),
				/* 383 last System call */
};

system_call_func sys_call_table_32[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 0 */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_time),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_stime),/* 25 */
	SYSTEM_CALL_TBL_ENTRY(sys_ptrace),
	SYSTEM_CALL_TBL_ENTRY(sys_alarm),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* old sys_fstat() */
	SYSTEM_CALL_TBL_ENTRY(sys_pause),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_utime),/* 30 */
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
	SYSTEM_CALL_TBL_ENTRY(sys_gettimeofday32),
	SYSTEM_CALL_TBL_ENTRY(sys_settimeofday32),
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
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_adjtimex),
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
	SYSTEM_CALL_TBL_ENTRY(compat_sys_sched_rr_get_interval),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_nanosleep),
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigreturn() */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigaction32),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigpending),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigtimedwait),
	SYSTEM_CALL_TBL_ENTRY(compat_sys_rt_sigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigsuspend),
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_vfork),	/* 190 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64), 
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195 , in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_lstat64),     /* in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_fstat64),     /* in libc used in ptr32 mode */
	
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl64),	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#ifdef CONFIG_MAC_
	SYSTEM_CALL_TBL_ENTRY(sys_macctl),	/* 223 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
#endif /* CONFIG_MAC_ */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_setjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_longjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone2 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 230 */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_futex),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_setaffinity),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	SYSTEM_CALL_TBL_ENTRY(sys_pipe2),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_backtrace),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_backtrace),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_access_hw_stacks),
#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix),	/* 255 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 255 */
#endif
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 256 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_set_tid_address),
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	SYSTEM_CALL_TBL_ENTRY(sys_el_binary), /* 260 Last valid system call*/
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */	
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_create),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_settime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_gettime),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_getoverrun),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_delete),	/* 265 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_settime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_gettime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_getres),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_nanosleep),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_getevents),  
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_utimes), 
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64), /* 310 */
        
        SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */ 
                                          /*The system call isn't implemented in the Linux 2.6.14
                                             * kernel  */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
#ifdef CONFIG_KEYS_COMPAT
	SYSTEM_CALL_TBL_ENTRY(compat_sys_keyctl),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_utimensat),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_recvmmsg),
#ifdef CONFIG_RECOVERY
	SYSTEM_CALL_TBL_ENTRY(sys_cnt_point),	/* 350 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 350 */
#endif
#ifdef CONFIG_TIMERFD
	SYSTEM_CALL_TBL_ENTRY(sys_timerfd_create),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timerfd_settime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timerfd_gettime),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_futimesat),
	SYSTEM_CALL_TBL_ENTRY(sys_perf_event_open),
	SYSTEM_CALL_TBL_ENTRY(sys_unshare),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_robust_list),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_robust_list),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_pselect6),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_ppoll),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_setcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_makecontext),	/* 370 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_swapcontext),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_freecontext),
	SYSTEM_CALL_TBL_ENTRY(sys_fanotify_init),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fanotify_mark),
	SYSTEM_CALL_TBL_ENTRY(sys_prlimit64),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_adjtime),
	SYSTEM_CALL_TBL_ENTRY(sys_syncfs),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sendmmsg),
	SYSTEM_CALL_TBL_ENTRY(sys_setns),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_process_vm_readv), /* 380 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_process_vm_writev),
	SYSTEM_CALL_TBL_ENTRY(sys_kcmp),
	SYSTEM_CALL_TBL_ENTRY(sys_finit_module),
				/* 383 last System call */
};


/*
 * If value of fast_sys_call_table[sys_num] == 1
 *  then we dont't use fast_sys_call
 *  It needs pt_regs .
 *  Added new case for compat_<proc> which can call compat_alloc_user_space
 *  Compat_alloc_user_space used  thread_info->pt_regs->stacks.usd
 *  and may call expand_user_data_stack
 *  For this case fast_sys_call_table[sys_num] will be equel 2
 *  if fast_sys_call_table[sys_num] == 2 &&  elf_32 code
 *  may be two case:
 *   1:   ss_stk_size > max_len (max param of compat_alloc_user_space) 
 *         added code in trap_table.S
 *   2:   call  ttable_entry2_C_32 (not optimal)     
 */  
const char fast_sys_call_table[NR_syscalls] =
{
	0,	                                /* 0 */
	0,
	1,                                      /* sys_fork */
	0,
	0,
	0,                                      /* 5 */
	0,
	0,
	0,
	0,
	0,                              	/* 10 */
	0,
	0,
	0,
	0,
	0,                              	/* 15 */
	0,
	1,                              	/* old break syscall holder */
	1,	                                /* old sys_stat() */
	0,
	0,                              	/* 20 */
	0,
	0,
	0,
	0,
	0,                              	/* 25 */
	0,
	0,
	1,                              	/* old sys_fstat() */
	0,
	0,                              	/* 30 */
	1,                              	/* old stty syscall holder */
	1,                              	/* old gtty syscall holder */
	0,
	0,
	1,                              	/* 35, old ftime syscall */
	0,
	0,
	0,
	0,
	0,                              	/* 40 */
	0,
	0,
	0,
	1,                              	/* old prof syscall holder */
	0,	                        	/* 45 */
	0,
	0,
	1, /* signal() have to be emulated by rt_sigaction() on user level (GLIBC) */
	0,
	0,                              	/* 50 */
	0,
	0,                              	/* recycled never used phys() */
	1,                              	/* old lock syscall holder */
	1,                                      /* sys_ioctl */
	0,                              	/* 55 */ /* for 64 & 32 */
	1,                              	/* old mpx syscall holder */
	0,
	1,                              	/* old ulimit syscall holder */
	1,
	0,                              	/* 60 */
	0,
	0,
	0,
	0,
	0,                              	/* 65 */
	0,
	1,                              	/* no sys_sigaction(), use    */
	0,                              	/* sys_rt_sigaction() instead */
	0,
	0,                              	/* 70 */
	0,
	1,
	0,
	0,
	0,                              	/* 75 */
	0,
	0,
	0,
	0,
	0,                              	/* 80 */
	0,
	1,
	0,
	1,                              	/* old sys_lstat() */
	0,                              	/* 85 */
	0,
	0,
	0,
	0,
	0,                              	/* 90 */
	0,
	0,
	0,
	0,
	0,                              	/* 95 */
	0,
	0,
	1,                              	/* old profil syscall holder */
	0,
	0,                              	/* 100 */
	0,
	0,
	0,
	0,
	0,                              	/* 105 */
	0,                                      /* in libc used in ptr64 mode */
	0,                                      /* in libc used in ptr64 mode */
	0,                                      /* in libc used in ptr64 mode */
	0,
	1,                              	/* 110 */
	0,
	1,                              	/* old "idle" system call */
	1,
	0,
	0,                              	/* 115 */
	0,
	1,                                      /* sys_ipc */
	0,
	1,
	1,                              	/* e2k_sys_clone 120 */
	0,
	0,
	1,
	0,
	0,                              	/* 125 */
	0,
	1,
	0,
	0,
	1,                                       /* 130 */
	0,
	0,
	0,
	0,
	0,                              	/* 135 */
	0,
	1,                              	/* for afs_syscall */
	0,
	0,
	0,                              	/* 140 */
	0,
	0,
	0,
	0,
	0,                              	/* 145 */
	0,
	0,
	0,
	0,
	0,                              	/* 150 */
	0,
	0,
	0,
	0,
	0,                                      /* 155 */
	0,
	0,
	0,
	0,
	0,                                      /* 160 */
	0,
	0,
	0,
	0,
	0,                              	/* 165 */
	1,
	1,
	0,
	0,
	0,                              	/* 170 */
	0,
	0,
	1,                                      /* sys_rt_sigreturn() */
	1,                                      /* sys_rt_sigaction */
	0,                              	/* 175 */
	0,
	0,
	0,
	0,
	0,                      		/* 180 */
	0,
	0,
	0,
	0,
	0,                              	/* 185 */
	1,                                      /* sys_sigaltstack */
	0,
        1,                              	/* streams1 */
	1,                              	/* streams2 */
	1,	                                /* e2k_sys_vfork 190 */
	0,
	0,
	1, 
	1,/* 193 & 194 entries are sys_truncate64 &sys_ftruncate64 in open.c
		if OS is for BITS_PER_LONG == 32 Our OS is for 64 */
	0,                              	/* 195 , in libc used in ptr32 mode */
	0,                                      /* in libc used in ptr32 mode */
	0,                                      /* in libc used in ptr32 mode */
	0,
	0,
	0,                              	/* 200 */
	0,
	0,
	0,
	0,
	0,                              	/* 205 */
	1,
	0,
	0,
	0,
	0,                              	/* 210 */
	0,
	0,
	0,
	0,
	0,                              	/* 215 */
	0,
	0,
	0,
	0,
	0,                              	/* 220 */
	0,	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	1,					/* sys_core */
#ifdef CONFIG_MAC_
	0,                              	/* 223 */
#else
	1,                              	/* 223 */
#endif /* CONFIG_MAC_ */
	1,
	1,                              	/* 225 */
	1,                                      /*sys_e2k_setjmp in traptable*/
	1,                                      /*sys_e2k_longjmp in traptable*/
	0,
	1,                              	/* sys_clone2 */ 
	1,                              	/* 230  sys_e2k_longjmp2*/
	1,
	0,
	0,
	0,
	0,                              	/* 235 */
	0,
	0,
	0,
	0,
	0,                              	/* 240 */
	0,
	0,
	0,
	0,
	0,                              	/* 245 */
	0,
	0,
	0,
	0,
	0,                              	/* 250 */
	1,/* !!!! for debug measure ttable_entry2 */
	1,/* !!!! for debug - print_ticks */
	1,/* !!!! for debug - measure generic_syscall */
	1,
	0,                                      /* 255 */
	1,                              	/* 256 */
	1,
	1,
	0,
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	0,                                      /* 260 Last valid system call*/
#else
	1,                              	/* 260 */
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */	
	0,
	0,
	0,
	0,
	0,                              	/* 265 */
	0,
	0,
	0,
	0,
	1,                              	/* 270 */
	1,
	1,
	1,
	1,
	1,                              	/* 275 */
	1,
	1,
	1,
	1,
	1,                              	/* 280 */
	1,
	1,
	1,
	1,
	1,                              	/* 285 */
	1,
	0,
	0,
	0,                              	/* 289 __NR_ioprio_set */
	0,                              	/* 290 __NR_ioprio_get */
	0,                                      /* 291 __NR_inotify_init */
	0,
						/* 292 __NR_inotify_add_watch */
	0,
						/* 293 __NR_inotify_rm_watch */
	0,                                      /* 294 */
	0,  
	2,  
	2,  
	0,  
	0,  
	0,                                       /* 300 */ 
	0, 
	0, 
	0, 
	0, 
	0, 
	0, 
	0, 
	0, 
	0,
	0,                                       /* 310 */
        1,                                       /*  __NR_vserver */ 
                                                 /*The system call isn't implemented
                                                 *  in the Linux 2.6.14 kernel 
                                                 */
	2,
	2,
	2,
	2,
	0,
	2,
	2,
	2,
	2,                                       /* 320 */
	2,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,					/* 330 */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,					/* 340 */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,					/* 350 */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,					/* 360 */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	1,					/* 369 sys_setcontext */
	1,					/* 370 sys_makecontext */
	1,					/* 371 sys_swapcontext */
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
						/* 383 last System call */
};


/* System call handlers for protected mode. If some system
 * call is not here it does not mean it is not implemented -
 * it is probably called from ttable_entry10 after reading
 * and preparing its parameters. */
const system_call_func sys_protcall_table[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 0 */
	SYSTEM_CALL_TBL_ENTRY(sys_exit),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// fork
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
			/* next 3 calls in libc used in ptr64 mode */
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// e2k_sys_clone
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_poll
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* was sys_nfsservctl */
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 170 */
	SYSTEM_CALL_TBL_ENTRY(sys_getresgid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_prctl
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigreturn() */
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
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_vfork),	/* 190 */
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
	
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_fchown),
	SYSTEM_CALL_TBL_ENTRY(sys_setresuid),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getresuid
	SYSTEM_CALL_TBL_ENTRY(sys_setresgid),	/* 210 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getresgid
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_setuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setgid),
	SYSTEM_CALL_TBL_ENTRY(sys_setfsuid),	/* 215 */
	SYSTEM_CALL_TBL_ENTRY(sys_setfsgid),
	SYSTEM_CALL_TBL_ENTRY(sys_pivot_root),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_mincore
	SYSTEM_CALL_TBL_ENTRY(sys_madvise),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_getdents64
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),		// sys_fcntl	
						/* 
	* 221 is sys_fcntl64 in fcntl.c
	* if BITS_PER_LONG == 32
	* for some other archs 
						*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#ifdef CONFIG_MAC_
	SYSTEM_CALL_TBL_ENTRY(sys_macctl),	/* 223 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
#endif /* CONFIG_MAC_ */

	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_setjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_longjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone2 */ 
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	// 251 pupe2
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_dup3),
	SYSTEM_CALL_TBL_ENTRY(sys_inotify_init1),
	SYSTEM_CALL_TBL_ENTRY(sys_epoll_create1),/* 360 */
	SYSTEM_CALL_TBL_ENTRY(sys_fstatat64),
	SYSTEM_CALL_TBL_ENTRY(sys_futimesat),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 380 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
						/* 383 last System call */
};


/* For the deprecated 4th syscall entry.
 * Since this system call entry is deprecated we use
 * sys_ni_syscall for all new entries from now on. */
system_call_func sys_call_table_deprecated[NR_syscalls] =
{
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 0 */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_time),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_stime),/* 25 */
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
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_clone),	/* 120 */
	SYSTEM_CALL_TBL_ENTRY(sys_setdomainname),
	SYSTEM_CALL_TBL_ENTRY(sys_newuname),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_adjtimex),
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
	SYSTEM_CALL_TBL_ENTRY(compat_sys_sched_rr_get_interval),
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
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_rt_sigreturn() */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigaction32),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigprocmask),	/* 175 */
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigpending),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_rt_sigtimedwait),
	SYSTEM_CALL_TBL_ENTRY(compat_sys_rt_sigqueueinfo),
	SYSTEM_CALL_TBL_ENTRY(sys_rt_sigsuspend),
	SYSTEM_CALL_TBL_ENTRY(sys32_pread64),		/* 180 */
	SYSTEM_CALL_TBL_ENTRY(sys32_pwrite64),
	SYSTEM_CALL_TBL_ENTRY(sys_chown),
	SYSTEM_CALL_TBL_ENTRY(sys_getcwd),
	SYSTEM_CALL_TBL_ENTRY(sys_capget),
	SYSTEM_CALL_TBL_ENTRY(sys_capset),	/* 185 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sigaltstack),
	SYSTEM_CALL_TBL_ENTRY(sys_sendfile),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams1 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* streams2 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_vfork),	/* 190 */
	SYSTEM_CALL_TBL_ENTRY(e2k_sys_getrlimit),
	SYSTEM_CALL_TBL_ENTRY(sys_mmap2),

	SYSTEM_CALL_TBL_ENTRY(sys32_truncate64), 
	SYSTEM_CALL_TBL_ENTRY(sys32_ftruncate64),
	SYSTEM_CALL_TBL_ENTRY(sys_stat64),	/* 195 , in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_lstat64),     /* in libc used in ptr32 mode */
	SYSTEM_CALL_TBL_ENTRY(sys_fstat64),     /* in libc used in ptr32 mode */
	
	SYSTEM_CALL_TBL_ENTRY(sys_lchown),
	SYSTEM_CALL_TBL_ENTRY(sys_getuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getgid),	/* 200 */
	SYSTEM_CALL_TBL_ENTRY(sys_geteuid),
	SYSTEM_CALL_TBL_ENTRY(sys_getegid),
	SYSTEM_CALL_TBL_ENTRY(sys_setreuid),
	SYSTEM_CALL_TBL_ENTRY(sys_setregid),
	SYSTEM_CALL_TBL_ENTRY(sys_lookup_dcookie),	/* 205 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_getdents64),	/* 220 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_fcntl),	
						/* 
						 * 221 is sys_fcntl64 in fcntl.c
						 * if BITS_PER_LONG == 32
						 * for some other archs 
						 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#ifdef CONFIG_MAC_
	SYSTEM_CALL_TBL_ENTRY(sys_macctl),	/* 223 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 223 */
#endif /* CONFIG_MAC_ */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 225 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_setjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),  /*sys_e2k_longjmp in traptable*/
	SYSTEM_CALL_TBL_ENTRY(sys_e2k_syswork),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* sys_clone2 */ 
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),	/* 230 */
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_futex),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_setaffinity),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_sched_getaffinity),	/* 250 */
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
	SYSTEM_CALL_TBL_ENTRY(sys_el_posix),	/* 255 */
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall), /* 255 */
#endif
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_settime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_timer_gettime),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_getoverrun),
	SYSTEM_CALL_TBL_ENTRY(sys_timer_delete),	/* 265 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_settime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_gettime),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_getres),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_clock_nanosleep),
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_io_getevents),  
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
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_utimes), 
	SYSTEM_CALL_TBL_ENTRY(sys32_fadvise64_64), /* 310 */
        
        SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),   /*  __NR_vserver */ 
                                          /*The system call isn't implemented in the Linux 2.6.14
                                             * kernel  */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mbind),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_get_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_set_mempolicy),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_open),
	SYSTEM_CALL_TBL_ENTRY(sys_mq_unlink),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_timedsend),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_timedreceive),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_notify),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_mq_getsetattr), /* 320 */
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_kexec_load),
	COMPAT_SYSTEM_CALL_TBL_ENTRY(sys_waitid),
	SYSTEM_CALL_TBL_ENTRY(sys_add_key),
	SYSTEM_CALL_TBL_ENTRY(sys_request_key),
#ifdef CONFIG_KEYS_COMPAT
	SYSTEM_CALL_TBL_ENTRY(compat_sys_keyctl),
#else
	SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall),
#endif
	/* This system call entry is deprecated so use
	 * sys_ni_syscall for all entries from now on. */
	[326 ... NR_syscalls - 1] = SYSTEM_CALL_TBL_ENTRY(sys_ni_syscall)
};

static int  __init merge_table(void)
{
	int i;
	int byte;

	for (i = 0; i < NR_syscalls; i++) {
		if ((byte = fast_sys_call_table[i]) != 0) {
			sys_call_table_deprecated[i] = (system_call_func)
			((long)sys_call_table_deprecated[i] |
			((long)byte << 56));
		    sys_call_table_32[i] = (system_call_func)
			((long)sys_call_table_32[i] |
			((long)byte << 56));
		    sys_call_table[i] = (system_call_func)
			((long)sys_call_table[i] |
			((long)byte << 56));
		}
	}
	return 0;
}
core_initcall(merge_table);

