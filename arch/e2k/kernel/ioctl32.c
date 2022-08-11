/*
 * linux/arch/e2k/kernel/ioctl32.c
 * Conversion between 32bit and 64bit native e2k ioctls.
 */

#include <linux/signal.h>
#include <linux/syscalls.h>

#define	INCLUDES
#include "compat_ioctl.c"

#define CODE
#include "compat_ioctl.c"

typedef int (* ioctl32_handler_t)(unsigned int, unsigned int, unsigned long,
				struct file *);
#define COMPATIBLE_IOCTL(cmd)		HANDLE_IOCTL((cmd),sys_ioctl)
#define HANDLE_IOCTL(cmd,handler)	{ (cmd), (ioctl32_handler_t)(handler), NULL },
#define IOCTL_TABLE_START \
	struct ioctl_trans ioctl_start[] = {
#define IOCTL_TABLE_END \
	};

IOCTL_TABLE_START
#define DECLARES
#include "compat_ioctl.c"
#include <linux/compat_ioctl.h>
IOCTL_TABLE_END

int ioctl_table_size = ARRAY_SIZE(ioctl_start);
