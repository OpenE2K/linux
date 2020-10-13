
OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
OUTPUT_ARCH(e2k)
ENTRY(start)

MEMORY {
 ROM (RX) : ORIGIN = 0xFFFF000000, LENGTH = 16M
 RAM (W) : ORIGIN = 1M, LENGTH = 31M

/* ROM chunks */
 ROML (RX) : ORIGIN = 0xFFFF000000, LENGTH = 8M
 ROMH (RX) : ORIGIN = 0xFFFF800000, LENGTH = 8M
 CPUSTART (RX) : ORIGIN = 0xFFFFFFF800, LENGTH = 8M
}

SECTIONS {

	_start = .;
	.text : {
	_text = .;		/* Text and read-only data */

		*(EXCLUDE_FILE (romstartup.o) .text .gnu.linkonce.t.*)
		*(EXCLUDE_FILE (romstartup.o piggy.o) .rodata)

		. = ALIGN(4096);
		piggy.o(.rodata)

	_etext = .;		/* End of text section */
	} > ROML

	.data : AT ( ADDR(.text) + SIZEOF ( .text ) ) {
	_data = .;		/* Data section */
		*(EXCLUDE_FILE (romstartup.o) .data .gnu.linkonce.d.*)


	_edata = .;		/* End of data section */
	} > RAM



	.bss : {
	__bss_start = .;	/* BSS */

		*(EXCLUDE_FILE (romstartup.o) .bss COMMON)

	__bss_end = . ;
	} > RAM

	.initrd : {
		*(.initrd)
	} > ROMH

	.symtable : {
		*(.symtable)
	} > ROMH

	.strtable : {
		*(.strtable)
	} > ROMH

	.text.startup : {
		__startup_start = .;

		romstartup.o(.text)
		romstartup.o(.rodata)
		romstartup.o(.data)
		romstartup.o(.bss)

		__startup_end = .;

		. = ALIGN(2048);   /* Round up the image size exactly to 16M. */

	} > CPUSTART

  /* Sections to be discarded */
  /DISCARD/ : {
		*(.info)
	}

	__bios_start_code  = ADDR(.text);
	__bios_size_code  = SIZEOF(.text);
	__bios_start_data  = ADDR(.text) + SIZEOF( .text );
	__bios_size_data  = SIZEOF(.data);
	__bios_size_data_plus_bss  = SIZEOF(.data) + SIZEOF( .bss );



  /* lld compatibility items. These calculations may be not quite accurate. */
	__bios_size_ld  = SIZEOF ( .text );
	__bios_fsize_ld = SIZEOF ( .text ) + SIZEOF ( .text ) + SIZEOF ( .bss );
	__bios_entry_ld = __startup_start - _text;
}
