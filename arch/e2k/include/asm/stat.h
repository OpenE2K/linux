#ifndef _E2K_STAT_H_
#define _E2K_STAT_H_

#include <uapi/asm/stat.h>


/*
 * "struct stat64" should be the same as glibc "struct stat64"
 */
struct stat64 {
	unsigned long		st_dev;
	unsigned long		st_ino;
	unsigned int		st_mode;
	unsigned int		st_nlink;
	unsigned int		st_uid;
	unsigned int		st_gid;
	unsigned long		st_rdev;
	unsigned long		st_size;
	unsigned int		st_blksize;
	unsigned int		__unused1;
	unsigned long		st_blocks;
	int			st_atime;
	unsigned int		st_atime_nsec;
	int			st_mtime;
	unsigned int		st_mtime_nsec;
	int			st_ctime;
	unsigned int		st_ctime_nsec;
};

#endif /* _E2K_STAT_H_ */
