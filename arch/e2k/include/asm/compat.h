#ifndef _ASM_E2K_COMPAT_H
#define _ASM_E2K_COMPAT_H

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <asm/regs_state.h>
#include <asm/debug_print.h>

#define COMPAT_USER_HZ	100

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_pid_t;
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u16		compat_mode_t;
typedef u32		compat_ino_t;
typedef u16		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef s16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_key_t;
typedef s32		compat_timer_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u32		compat_uptr_t;

typedef u64		compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	compat_off_t	st_size;
	compat_time_t	st_atime;
	compat_ulong_t	st_atime_nsec;
	compat_time_t	st_mtime;
	compat_ulong_t	st_mtime_nsec;
	compat_time_t	st_ctime;
	compat_ulong_t	st_ctime_nsec;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	u32		__unused4[2];
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
	short		__unused;
};

#define F_GETLK64	12
#define F_SETLK64	13
#define F_SETLKW64	14

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
	short		__unused;
};

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;
	int		f_frsize;
	int		f_flags;
	int		f_spare[4];
};

#define COMPAT_RLIM_INFINITY 0x7fffffff

typedef u32		compat_old_sigset_t;

#undef  DebugUS
#define	DEBUG_US		0       /* Allocate User Space */
#define DebugUS(...)		DebugPrint(DEBUG_US ,##__VA_ARGS__)


#define _COMPAT_NSIG		64
#define _COMPAT_NSIG_BPW	32

typedef u32		compat_sigset_word;

typedef union compat_sigval {
	compat_int_t	sival_int;
	compat_uptr_t	sival_ptr;
} compat_sigval_t;

typedef struct compat_siginfo {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		int _pad[SI_PAD_SIZE32];

		/* kill() */
		struct {
			compat_pid_t _pid;		/* sender's pid */
			unsigned int _uid;		/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			compat_timer_t _tid;	/* timer id */
			int _overrun;		/* overrun count */
			compat_sigval_t _sigval;	/* same as below */
			int _sys_private;	/* not to be passed to user */
			int _overrun_incr;	/* amount to add to overrun */
		} _timer;

		/* POSIX.1b signals */
		struct {
			compat_pid_t _pid;		/* sender's pid */
			unsigned int _uid;		/* sender's uid */
			compat_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			compat_pid_t _pid;		/* which child */
			unsigned int _uid;		/* sender's uid */
			int _status;			/* exit code */
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;

		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGEMT */
		struct {
			u32 _addr; /* faulting insn/memory ref. */
			int _trapno;
		} _sigfault;

		/* SIGPOLL */
		struct {
			int _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		struct {
			unsigned int _call_addr; /* calling insn */
			int _syscall;   /* triggering system call number */
			unsigned int _arch;     /* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
} compat_siginfo_t;

typedef struct sigevent32 {
	sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[SIGEV_PAD_SIZE32];

		struct {
			u32 _function;
			u32 _attribute;	/* really pthread_attr_t */
		} _sigev_thread;
	} _sigev_un;
} sigevent_t32;

extern long sys_rt_sigaction32(int sig, const struct sigaction *act,
			       struct sigaction *oact, size_t sigsetsize);

#define COMPAT_OFF_T_MAX	0x7fffffff
#define COMPAT_LOFF_T_MAX	0x7fffffffffffffffL

/*
 * The type of struct elf_prstatus.pr_reg in compatible core dumps.
 */
typedef struct user_regs_struct compat_elf_gregset_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static __inline__ void __user *arch_compat_alloc_user_space(unsigned long len)
{
	thread_info_t *thread_info = current_thread_info();
	pt_regs_t *user_regs = thread_info->pt_regs;
	u64 ss_stk_size;
	e2k_usd_hi_t	ss_usd_hi;


	ss_usd_hi	= thread_info->u_usd_hi;
	ss_stk_size 	=  AS_STRUCT(ss_usd_hi).size;

        
        // check  stk_size	
	while (ss_stk_size < len ) {
		/* In this case  user_regs must be valid */
		DebugUS("user stack size "
			" 0x%llx < 0x%lx  needed to expand_user_data_stack\n",
			ss_stk_size, len);
		if (user_regs == NULL) {
			return 0;
		}
		expand_user_data_stack(user_regs, current, false);
		ss_usd_hi	= user_regs->stacks.usd_hi;
		ss_stk_size 	= AS_STRUCT(ss_usd_hi).size;
                DebugUS("compat_alloc_user_space expanded stack: size "
                        "0x%llx\n", ss_stk_size);
	}
        DebugUS("%llx ss_stk_size=%llx\n", 
		thread_info->u_usd_lo.USD_lo_base, ss_stk_size);

	return (void __user *)(thread_info->u_usd_lo.USD_lo_base - len);
}
#define __copy_in_user copy_in_user

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short __pad1;
	compat_mode_t mode;
	unsigned short __pad2;
	unsigned short seq;
	unsigned long __unused1;	/* yes they really are 64bit pads */
	unsigned long __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	unsigned int	__pad1;
	compat_time_t	sem_otime;
	unsigned int	__pad2;
	compat_time_t	sem_ctime;
	u32		sem_nsems;
	u32		__unused1;
	u32		__unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	unsigned int	__pad1;
	compat_time_t	msg_stime;
	unsigned int	__pad2;
	compat_time_t	msg_rtime;
	unsigned int	__pad3;
	compat_time_t	msg_ctime;
	unsigned int	msg_cbytes;
	unsigned int	msg_qnum;
	unsigned int	msg_qbytes;
	compat_pid_t	msg_lspid;
	compat_pid_t	msg_lrpid;
	unsigned int	__unused1;
	unsigned int	__unused2;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	unsigned int	__pad1;
	compat_time_t	shm_atime;
	unsigned int	__pad2;
	compat_time_t	shm_dtime;
	unsigned int	__pad3;
	compat_time_t	shm_ctime;
	compat_size_t	shm_segsz;
	compat_pid_t	shm_cpid;
	compat_pid_t	shm_lpid;
	unsigned int	shm_nattch;
	unsigned int	__unused1;
	unsigned int	__unused2;
};
#define __put_user_unaligned __put_user

static inline int is_compat_task(void)
{
	return current->thread.flags & E2K_FLAG_32BIT;
}

#endif /* _ASM_E2K_COMPAT_H */
