#ifndef _E2K_UNISTD_H_
#define _E2K_UNISTD_H_

#include <linux/types.h>
#ifndef	__ASSEMBLY__
#include <asm/e2k_api.h>
#endif	/* __ASSEMBLY__ */
#include <uapi/asm/unistd.h>

#define NR_fast_syscalls_mask	0x7
#define NR_fast_syscalls	8

#define	NR_syscalls		384

#define	__NR__brk		__NR_brk
#define	__NR_newstat		__NR_stat
#define	__NR_newlstat		__NR_lstat
#define	__NR_newfstat		__NR_fstat


#define __IGNORE_name_to_handle_at
#define __IGNORE_open_by_handle_at

/* On e2k these are called "pread" and "pwrite" */
#define __IGNORE_pread64
#define __IGNORE_pwrite64


#define __ARCH_WANT_OLD_READDIR
#define __ARCH_WANT_OLD_STAT
#define __ARCH_WANT_STAT64
#define __ARCH_WANT_SYS_ALARM
#define __ARCH_WANT_SYS_GETHOSTNAME
#define __ARCH_WANT_SYS_IPC
#define __ARCH_WANT_SYS_PAUSE
#define __ARCH_WANT_SYS_SGETMASK
#define __ARCH_WANT_SYS_SIGNAL
#define __ARCH_WANT_SYS_TIME
#define __ARCH_WANT_SYS_UTIME
#define __ARCH_WANT_SYS_WAITPID
#define __ARCH_WANT_SYS_SOCKETCALL
#define __ARCH_WANT_SYS_FADVISE64
#define __ARCH_WANT_SYS_GETPGRP
#define __ARCH_WANT_SYS_LLSEEK
#define __ARCH_WANT_SYS_NEWFSTATAT
#define __ARCH_WANT_SYS_NICE
#define __ARCH_WANT_SYS_OLD_GETRLIMIT
#define __ARCH_WANT_SYS_OLDUMOUNT
#define __ARCH_WANT_SYS_SIGPENDING
#define __ARCH_WANT_SYS_SIGPROCMASK
#define __ARCH_WANT_COMPAT_SYS_TIME

#endif /* _E2K_UNISTD_H_ */
