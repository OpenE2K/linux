
OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
/* OUTPUT_ARCH(e2k) Defined by Makefile */
ENTRY(start)

MEMORY {
 ROM (RX) : ORIGIN = 0xFFFF000000, LENGTH = 16M
 RAM (W) : ORIGIN = 1M, LENGTH = 31M

/* ROM chunks */
 ROMU (RX) : ORIGIN = 0xFFFF000000, LENGTH = 16M - 2048
 CPUSTART (RX) : ORIGIN = 0xFFFFFFF800, LENGTH = 2048
}

SECTIONS {

	_start = .;
	.text : {
	_text = .;		/* Text and read-only data */

		*(EXCLUDE_FILE (arch/e2k/boot/romstartup.o arch/e2k/boot/apstartup.o) .text .gnu.linkonce.t.*)
		*(EXCLUDE_FILE (arch/e2k/boot/romstartup.o piggy.o) .rodata)

		. = ALIGN(4096);
		piggy.o(.rodata)

	_etext = .;		/* End of text section */
	} > ROMU

	.initrd : AT ( ADDR(.text) + SIZEOF ( .text ) ) {
		*(.initrd)      /* Not in .data section so as not to copy */
	} > ROMU                /* unnecessary data in romloader.S        */

	.data : AT ( ADDR(.initrd) + SIZEOF ( .initrd ) ) {
	_data = .;		/* Data section */
		__apstartup_start = .;
		arch/e2k/boot/apstartup.o(.text)
		__apstartup_end = .;
		*(EXCLUDE_FILE (arch/e2k/boot/romstartup.o) .data .gnu.linkonce.d.*)

	_edata = .;		/* End of data section */
	} > RAM

	.bss : AT ( ADDR(.data) + SIZEOF ( .data )) {
	__bss_start = .;	/* BSS */

		*(EXCLUDE_FILE (arch/e2k/boot/romstartup.o) .bss COMMON)

	__bss_stop = . ;
	} > RAM

	.text.startup : {
		__startup_start = .;

		arch/e2k/boot/romstartup.o(.text)
		arch/e2k/boot/romstartup.o(.rodata)
		arch/e2k/boot/romstartup.o(.data)
		arch/e2k/boot/romstartup.o(.bss)

		__startup_end = .;

		. = ALIGN(2048);   /* Round up the image size exactly to 16M. */

	} > CPUSTART

  /* Sections to be discarded */
  /DISCARD/ : {
		*(.info)
	}

	__bios_start_code  = ADDR(.text);
	__bios_size_code  = SIZEOF(.text);
	__bios_start_data  = ADDR(.initrd) + SIZEOF( .initrd );
	__bios_size_data  = SIZEOF(.data);
	__bios_size_data_plus_bss  = SIZEOF(.data) + SIZEOF( .bss );

  /* lld compatibility items. These calculations may be not quite accurate. */
	__bios_size_ld  = SIZEOF ( .text );
	__bios_fsize_ld = SIZEOF ( .text ) + SIZEOF ( .text ) + SIZEOF ( .bss );
	__bios_entry_ld = __startup_start - _text;
}
