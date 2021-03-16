/*
 *  drivers/mcst/dmp_assist/dmp_assist.h
 */

#ifndef DMP_ASSIST_H
#define DMP_ASSIST_H

#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/errno.h>

static char *dev_path = "/dev/dmp_assist";

#define MAJOR_NUM			242
#define DMP_ASSIST_NUM			212

#define IOCTL_DMP_ASSIST_kernel_base	_IO(DMP_ASSIST_NUM, 1)

#endif /* DMP_ASSIST_H */

