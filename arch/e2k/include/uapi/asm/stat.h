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
	unsigned int	st_dev;
	unsigned long	st_ino;
	unsigned int	st_mode;
	unsigned int	st_nlink;
	unsigned int	st_uid;
	unsigned int	st_gid;
	unsigned int 	st_rdev;
	long			st_size;
	long			st_blksize;
	long			st_blocks;
	long			st_atime;
	unsigned long	st_atime_nsec;
	long			st_mtime;
	unsigned long	st_mtime_nsec;
	long			st_ctime;
	unsigned long	st_ctime_nsec;
};


#endif /* _UAPI_E2K_STAT_H_ */
