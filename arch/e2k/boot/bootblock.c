/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/types.h>
#include <asm/bootinfo.h>
#include <asm/cpu_regs_types.h>

#include <uapi/asm/iset_ver.h>

extern u64 __kernel_size;

#if !defined(CONFIG_E2K_MACHINE)
# define TARGET_MDL		0
# define TARGET_ISET_MIN	CONFIG_CPU_ISET_MIN
# define TARGET_ISET_MAX	E2K_ISET_V6
#else
# define TARGET_ISET_MIN	0
# define TARGET_ISET_MAX	0
# if defined(CONFIG_E2K_E2S)
#  define TARGET_MDL		IDR_E2S_MDL
# elif defined(CONFIG_E2K_E8C)
#  define TARGET_MDL		IDR_E8C_MDL
# elif defined(CONFIG_E2K_E1CP)
#  define TARGET_MDL		IDR_E1CP_MDL
# elif defined(CONFIG_E2K_E8C2)
#  define TARGET_MDL		IDR_E8C2_MDL
# elif defined(CONFIG_E2K_E12C)
#  define TARGET_MDL		IDR_E12C_MDL
# elif defined(CONFIG_E2K_E16C)
#  define TARGET_MDL		IDR_E16C_MDL
# elif defined(CONFIG_E2K_E2C3)
#  define TARGET_MDL		IDR_E2C3_MDL
# elif defined(CONFIG_E2K_E8V7)
#  define TARGET_MDL		IDR_E8V7_MDL
# else
#  error "E2K MACHINE type does not defined"
# endif
#endif

const char gap[256] = {0};

const struct bootblock_struct boot_block =
{
	info: {
		signature : BOOTBLOCK_BOOT_SIGNATURE,	/* signature */
		target_mdl : TARGET_MDL,		/* target mdl */
		target_iset_min : TARGET_ISET_MIN,	/* target minimal iset version */
		target_iset_max : TARGET_ISET_MAX,	/* target maximum iset version */
		kernel_size : (u64)&__kernel_size,	/* kernel size */
#ifdef CONFIG_CMDLINE
		kernel_args_string : CONFIG_CMDLINE,	/* kernel command line */
#endif
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

