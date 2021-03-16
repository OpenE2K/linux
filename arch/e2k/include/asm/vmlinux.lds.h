#ifndef __ASM_E2K_VMLINUX_LDS_H
#define __ASM_E2K_VMLINUX_LDS_H

#include <asm-generic/vmlinux.lds.h>

#define E2K_BOOT_SETUP(bootsetup_align)				\
	.boot.data : AT(ADDR(.boot.data) - LOAD_OFFSET) {	\
		. = ALIGN(bootsetup_align);			\
		__boot_setup_start = .;				\
		*(.boot.setup)					\
		__boot_setup_end = .;				\
	}

#endif /* __ASM_E2K_VMLINUX_LDS_H */
