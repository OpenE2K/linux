/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/config.h>
#include <asm/types.h>
#include <asm/bootinfo.h>

extern u64 __kernel_size;


const struct bootblock_struct boot_block =
{
	BOOTBLOCK_BOOT_SIGNATURE,	/* signature */
	0, 0, 0,			/* boot disk C/H/S */
	0,				/* vga mode  */
	0,				/* number of memory banks */
	0UL,				/* kernel base */
	(u64) & __kernel_size,		/* kernel size */
	0UL,				/* ramdisk base */
	0UL,				/* ramdisk size */
	CONFIG_CMDLINE,			/* kernel command line */
};
