/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/types.h>
#include <asm/bootinfo.h>

extern u64 __kernel_size;

const char gap[256] = {0};

const struct bootblock_struct boot_block =
{
	info: {
		signature : BOOTBLOCK_BOOT_SIGNATURE,	/* signature */
		kernel_size : (u64)&__kernel_size,	/* kernel size */
		kernel_args_string : CONFIG_CMDLINE,	/* kernel command line */
		bios : {
			s3_info: {
				ram_addr : -1ULL,
				size : -1ULL,
			}
		}
	},
	bootblock_ver : BOOTBLOCK_VER,	/* bootblock version number */
	bootblock_marker : 0xAA55	/* bootblock marker */
};

