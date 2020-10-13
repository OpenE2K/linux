/*
 * gld script to make E2K Linux kernel
 * Written by Linar Yusupov <linar@mcst.ru>;
 */

OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")
OUTPUT_ARCH(e2k)
ENTRY(_start)
SECTIONS
{
  . = 0xe2000000000;		/* KERNEL BASE VA ~ 14 * 2^40 */
  _start = .;			/* Start of kernel image */
  _text = .;			/* Text and read-only data */
  _stext = .;			/* Text and read-only data */
  .text : {
	*(.text)
	*(.fixup)
	*(.gnu.warning)
	*(.rodata)
	*(.kstrtab)

  . = ALIGN(4096);
  __init_begin = .;

  __init_text_begin = .;
  *(.text.init)
  __init_text_end = .;
	_etext = .;			/* End of text section */

  }
  . = ALIGN(4096);

  .data : {

	_sdata = .;			/* Start of data segment */

  __init_text_end = .;
  __init_data_begin = .;
  *(.data.init)
  . = ALIGN(16);
  __setup_start = .;
  *(.setup.init)
  __setup_end = .;

  __initcall_start = .;
  *(.initcall.init)
  __initcall_end = .;
  
  __boot_setup_start = .;
  *(.setup.boot)
  __boot_setup_end = .;

  . = ALIGN(4096);
  __init_data_end = .;
  __init_end = .;

	arch/e2k/kernel/page_tables.o(.data)
	*(EXCLUDE_FILE (arch/e2k/kernel/page_tables.o) .data)

	/*
	 * Taken from i386 gld script. Needed to resolve __start___ex_table &
	 * etc access from the kernel C-code.
	 */

	. = ALIGN(16);		/* Exception table */
	__start___ex_table = .;
	*(__ex_table)
	__stop___ex_table = .;

	__start___ksymtab = .;	/* Kernel symbol table */
	*(__ksymtab)
	__stop___ksymtab = .;

	CONSTRUCTORS
	. = ALIGN(16);

 	_edata = .;			/* End of data section */
  }

  /*
   * Taken from i386 gld script. Needed to resolve __setup_start & etc
   * access from the kernel C-code.
   */

  . = ALIGN(8192);		/* init_task */
  .data.init_task : { *(.data.init_task) }

   /* Init code */
/*
  . = ALIGN(4096);
  __init_begin = .;

  __init_text_begin = .;
  .text.init : { *(.text.init) }
*/
   /* Init data */
/*
  . = ALIGN(4096);
  __init_text_end = .;
  __init_data_begin = .;
  .data.init : { *(.data.init) }
  . = ALIGN(16);
  __setup_start = .;
  .setup.init : { *(.setup.init) }
  __setup_end = .;
  __initcall_start = .;
  .initcall.init : { *(.initcall.init) }
  __initcall_end = .;
  __boot_setup_start = .;
  .setup.boot : { *(.setup.boot) }
  __boot_setup_end = .;

  . = ALIGN(4096);
  __init_data_end = .;
  __init_end = .;
*/

  . = ALIGN(32);
  .data.cacheline_aligned : { *(.data.cacheline_aligned) }

  __bss_start = .;		/* BSS */
  .bss : {
	*(.bss)
	}
  __bss_end = . ;

  _end = . ;			/* End of everything */

  /* Sections to be discarded */
  /DISCARD/ : {
	*(.text.exit)
	*(.data.exit)
	*(.exitcall.exit)
	}

  .comment 0 : { *(.comment) }
}
