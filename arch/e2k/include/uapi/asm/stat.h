/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _UAPI_E2K_STAT_H_
#define _UAPI_E2K_STAT_H_

/*
 * Tuned up to match GNU libc defaults.
 */

#include <linux/types.h>

#define	STAT_HAVE_NSEC	1

struct __old_kernel_stat {
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned long  st_size;
	unsigned long  st_atime;
	unsigned long  st_mtime;
	unsigned long  st_ctime;
};

#ifdef __ptr32__
struct stat {
	__u32 st_dev;
	__u32 st_ino;
	__u16 st_mode;
	__s16 st_nlink;
	__u16 st_uid;
	__u16 st_gid;
	__u32 st_rdev;
	__s32 st_size;
	__s32 st_atime;
	__u32 st_atime_nsec;
	__s32 st_mtime;
	__u32 st_mtime_nsec;
	__s32 st_ctime;
	__u32 st_ctime_nsec;
	__s32 st_blksize;
	__s32 st_blocks;
	__u32 __unused[2];
};
#else
struct stat {
	unsigned long st_dev;
	unsigned long st_ino;
	unsigned int  st_mode;
	unsigned int  st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned long st_rdev;
	long st_size;
	long st_blksize;
	long st_blocks;
	long st_atime;
	unsigned long st_atime_nsec;
	long st_mtime;
	unsigned long st_mtime_nsec;
	long st_ctime;
	unsigned long st_ctime_nsec;
};
#endif

#endif /* _UAPI_E2K_STAT_H_ */
