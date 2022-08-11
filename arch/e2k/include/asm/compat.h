#ifndef _ASM_E2K_COMPAT_H
#define _ASM_E2K_COMPAT_H

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>

#include <asm/regs_state.h>
#include <asm/traps.h>
#include <asm/debug_print.h>

#include <asm-generic/compat.h>

#define COMPAT_USER_HZ	100

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
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
typedef s64		compat_s64;

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

#define COMPAT_OFF_T_MAX	0x7fffffff

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

extern void __user *arch_compat_alloc_user_space(unsigned long len);

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
	compat_ulong_t	__unused1;
	compat_ulong_t	sem_otime;
	compat_ulong_t	sem_otime_high;
	compat_ulong_t	sem_ctime;
	compat_ulong_t	sem_nsems;
	compat_ulong_t	sem_ctime_high;
	compat_ulong_t	__unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_ulong_t	__unused1;
	compat_ulong_t	msg_stime;
	compat_ulong_t	msg_stime_high;
	compat_ulong_t	msg_rtime;
	compat_ulong_t	msg_rtime_high;
	compat_ulong_t	msg_ctime;
	compat_ulong_t	msg_cbytes;
	compat_ulong_t	msg_qnum;
	compat_ulong_t	msg_qbytes;
	compat_pid_t	msg_lspid;
	compat_pid_t	msg_lrpid;
	compat_ulong_t	msg_ctime_high;
	compat_ulong_t	__unused2;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_ulong_t	__unused1;
	compat_ulong_t	shm_atime;
	compat_ulong_t	shm_atime_high;
	compat_ulong_t	shm_dtime;
	compat_ulong_t	shm_dtime_high;
	compat_ulong_t	shm_ctime;
	compat_size_t	shm_segsz;
	compat_pid_t	shm_cpid;
	compat_pid_t	shm_lpid;
	compat_ulong_t	shm_nattch;
	compat_ulong_t	shm_ctime_high;
	compat_ulong_t	__unused2;
};

static inline int is_compat_task(void)
{
	return (TASK_IS_PROTECTED(current)) ? 0 :
				(current->thread.flags & E2K_FLAG_32BIT);
}

#endif /* _ASM_E2K_COMPAT_H */
