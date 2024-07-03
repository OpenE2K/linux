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

struct stat {
	dev_t	st_dev;
	ino_t	st_ino;
	mode_t	st_mode;
	nlink_t	st_nlink;
	uid_t	st_uid;
	gid_t	st_gid;
	dev_t	st_rdev;
	off_t	st_size;
	off_t	st_blksize;
	off_t	st_blocks;
	__kernel_old_time_t	st_atime;
	unsigned long		st_atime_nsec;
	__kernel_old_time_t	st_mtime;
	unsigned long		st_mtime_nsec;
	__kernel_old_time_t	st_ctime;
	unsigned long		st_ctime_nsec;
};

#endif /* _UAPI_E2K_STAT_H_ */
