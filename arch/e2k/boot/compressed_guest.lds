/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
/* OUTPUT_ARCH(e2k) Defined by Makefile */
ENTRY(start)

SECTIONS {
	_start = .;
	.bootblock : {
		_bootblock = .;
			arch/e2k/boot/bootblock.o(.rodata)
		_ebootblock = .;
	}

	. = _bootblock + 0x10000;

	.loader : {
		. += 0x10000;
		*(.boot_entry)
		*(.text)
		*(EXCLUDE_FILE (arch/e2k/boot/cpiggy.o) .rodata)
		*(.data)

		_bss = .;
		*(.bss)
		_ebss = .;
	}
	.kernel : {
		_kernel = .;
		arch/e2k/boot/cpiggy.o(.rodata)
		_ekernel = .;
	}
	.got : {
		_got = .;
		*(.got)
		_egot = .;
	}
	_end = .;
}
