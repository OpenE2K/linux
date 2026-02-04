/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_COMPAT_H
#define _ASM_E2K_COMPAT_H

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>

#include <asm/regs_state.h>
#include <asm/traps.h>
#include <asm/debug_print.h>

#define compat_mode_t	compat_mode_t
typedef u16		compat_mode_t;

#define __compat_uid_t	__compat_uid_t
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;

#define compat_dev_t	compat_dev_t
typedef u16		compat_dev_t;

#define compat_ipc_pid_t compat_ipc_pid_t
typedef u16		 compat_ipc_pid_t;

#define compat_ipc64_perm compat_ipc64_perm

#include <asm-generic/compat.h>

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
	unsigned long __unused1;        /* yes they really are 64bit pads */
	unsigned long __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_ulong_t __unused1;
	compat_ulong_t sem_otime;
	compat_ulong_t sem_otime_high;
	compat_ulong_t sem_ctime;
	compat_ulong_t sem_nsems;
	compat_ulong_t sem_ctime_high;
	compat_ulong_t __unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_ulong_t __unused1;
	compat_ulong_t msg_stime;
	compat_ulong_t msg_stime_high;
	compat_ulong_t msg_rtime;
	compat_ulong_t msg_rtime_high;
	compat_ulong_t msg_ctime;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t msg_lspid;
	compat_pid_t msg_lrpid;
	compat_ulong_t msg_ctime_high;
	compat_ulong_t __unused2;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_ulong_t __unused1;
	compat_ulong_t shm_atime;
	compat_ulong_t shm_atime_high;
	compat_ulong_t shm_dtime;
	compat_ulong_t shm_dtime_high;
	compat_ulong_t shm_ctime;
	compat_size_t shm_segsz;
	compat_pid_t shm_cpid;
	compat_pid_t shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t shm_ctime_high;
	compat_ulong_t __unused2;
};

#define COMPAT_USER_HZ	100

typedef s16		compat_nlink_t;

struct compat_stat {
	compat_dev_t	st_dev;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	compat_off_t	st_size;
	old_time32_t	st_atime;
	compat_ulong_t	st_atime_nsec;
	old_time32_t	st_mtime;
	compat_ulong_t	st_mtime_nsec;
	old_time32_t	st_ctime;
	compat_ulong_t	st_ctime_nsec;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	u32		__unused4[2];
};

#define F_GETLK64	12
#define F_SETLK64	13
#define F_SETLKW64	14

#define COMPAT_OFF_T_MAX	0x7fffffff

/*
 * The type of struct elf_prstatus.pr_reg in compatible core dumps.
 */
typedef struct user_regs_struct compat_elf_gregset_t;

extern void __user *arch_compat_alloc_user_space(unsigned long len);

static inline int is_compat_task(void)
{
	return (TASK_IS_PROTECTED(current)) ? 0 :
			(current->thread.flags & E2K_FLAG_32BIT);
}

#ifdef CONFIG_COMPAT
static inline bool in_compat_syscall(void)
{
	struct pt_regs *regs = current_thread_info()->pt_regs;

	if (regs && regs->kernel_entry > 0)
		return regs->kernel_entry == 1;

	return is_compat_task();
}
#define in_compat_syscall in_compat_syscall     /* override the generic impl */
#endif

#endif /* _ASM_E2K_COMPAT_H */
