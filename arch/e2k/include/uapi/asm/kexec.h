#ifndef	_UAPI_E2K_KEXEC_H_
#define	_UAPI_E2K_KEXEC_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define	E2K_KEXEC_IOCTL_BASE	'E'

struct kexec_reboot_param {
	char	*cmdline;
	int	cmdline_size;
	void	*image;
	u64	image_size;
	void	*initrd;
	u64	initrd_size;
};

struct lintel_reboot_param {
	void	*image;
	u64	image_size;
};

#define	KEXEC_REBOOT  _IOR(E2K_KEXEC_IOCTL_BASE, 0, struct kexec_reboot_param)
#define	LINTEL_REBOOT _IOR(E2K_KEXEC_IOCTL_BASE, 0, struct lintel_reboot_param)

#endif
