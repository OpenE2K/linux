#include <asm/types.h>
#include <asm/bootinfo.h>

extern u64 __kernel_size;

const char gap[256] = {0};

const struct bootblock_struct boot_block =
{
	info: {
		signature : X86BOOT_SIGNATURE,	     /* signature */
		kernel_size : (u64)&__kernel_size,   /* kernel size */
		kernel_args_string : CONFIG_CMDLINE, /* kernel command line */
	},
	bootblock_ver : BOOTBLOCK_VER,	/* bootblock version number */
	x86_marker : 0xAA55		/* x86 marker */
};

