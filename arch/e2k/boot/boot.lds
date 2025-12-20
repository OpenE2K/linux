/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
/* OUTPUT_ARCH(e2k) Defined by Makefile */
ENTRY(start)

SECTIONS {
	.bootblock : {
		_bootblock = .;
		arch/e2k/boot/bootblock.o(.rodata)
		_ebootblock = .;
	}

	. = _bootblock + 0x10000;

	.kernel : {
		_kernel = .;
		arch/e2k/boot/bpiggy.o(.rodata)
		_ekernel = .;
	}
}
