/*
 * This is the GNU ld script to construct E2K Linux kernel
 */

#include <asm/cache.h>
#include <asm/vmlinux.lds.h>
#include <asm/head.h>

OUTPUT_FORMAT("elf64-e2k", "elf64-e2k", "elf64-e2k")

#ifdef	CONFIG_E2K_MACHINE
 #if defined(CONFIG_E2K_E3M) || defined(CONFIG_E2K_E3M_SIM)
 OUTPUT_ARCH(e3m)
 #elif defined(CONFIG_E2K_E3M_IOHUB) || defined(CONFIG_E2K_E3M_IOHUB_SIM)
 OUTPUT_ARCH(e3m)
 #elif defined(CONFIG_E2K_E3S) || defined(CONFIG_E2K_E3S_SIM)
 OUTPUT_ARCH(e3s)
 #elif defined(CONFIG_E2K_ES2_DSP) || defined(CONFIG_E2K_ES2_DSP_SIM) || \
	defined(CONFIG_E2K_ES2_RU) || defined(CONFIG_E2K_ES2_RU_SIM)
 OUTPUT_ARCH(e3s)
 #elif defined(CONFIG_E2K_E2S) || defined(CONFIG_E2K_E2S_SIM)
 OUTPUT_ARCH(e3s)
 #elif defined(CONFIG_E2K_E8C) || defined(CONFIG_E2K_E8C_SIM)
 OUTPUT_ARCH(e3s)
 #elif defined(CONFIG_E2K_E1CP) || defined(CONFIG_E2K_E1CP_SIM)
 OUTPUT_ARCH(e3s)
 #elif defined(CONFIG_E2K_E8C2) || defined(CONFIG_E2K_E8C2_SIM)
 OUTPUT_ARCH(e3s)
 #else
 error "Invalid e2k machine type"
 #endif	/* all machines types */
#else	/* ! CONFIG_E2K_MACHINE */
OUTPUT_ARCH(e2k)
#endif	/* CONFIG_E2K_MACHINE */

ENTRY(_start)
jiffies = jiffies_64;
SECTIONS
{
  . = E2K_KERNEL_IMAGE_AREA_BASE;	/* KERNEL BASE VA ~ 14 * 2^44 */
  _start = .;				/* Start of kernel image */
  _text = .;				/* Text and read-only data */
  _stext = .;				/* Text and read-only data */
  .text : {
		_t_entry = .;
			*(.ttable_entry0)
			. = _t_entry + 0x800;
			*(.ttable_entry1)
			. = _t_entry + 0x1800;
			*(.ttable_entry3)
			. = _t_entry + 0x2000;
			*(.ttable_entry4)
			. = _t_entry + 0x2800;
#ifdef CONFIG_COMPAT
			*(.ttable_entry5)
			*(.ttable_entry5_table)
			*(.ttable_entry5_C)
#endif
			. = _t_entry + 0x3000;
			*(.ttable_entry6)
			*(.ttable_entry6_table)
			*(.ttable_entry6_C)
#ifdef CONFIG_PROTECTED_MODE
			. = _t_entry + 0x3800;
			*(.ttable_entry7)
			*(.ttable_entry7_table)
			*(.ttable_entry7_C)
#endif
#ifdef CONFIG_PROTECTED_MODE
			. = _t_entry + 0x5000;
			*(.ttable_entry10)
			*(.ttable_entry10_C)
#endif
			. = _t_entry + 0x6000;
			*(.ttable_entry12)
		_t_entry_end = .;
		__entry_handlers_start = .;
		*(.entry_handlers)
		__entry_handlers_end = .;
                IRQENTRY_TEXT
		HEAD_TEXT
#ifdef CONFIG_KPROBES
		KPROBES_TEXT
#endif
		TEXT_TEXT
		SCHED_TEXT
		LOCK_TEXT
		*(.fixup)
		*(.gnu.warning)
	} /*:text*/
	NOTES /*:kernel :note*/
	.dummy : {
		*(.dummy)
	} /*:kernel*/

	RO_DATA_SECTION(PAGE_SIZE)

	_etext = .;			/* End of text section */

	. = ALIGN(E2K_MAX_PAGE_SIZE);

#ifdef CONFIG_KERNEL_CODE_CONTEXT
	_ptext_start = .;			/* Text protected */
	.protect.text : {
		*(.protect.text)
	}
	_ptext_end = .;
#endif

	. = ALIGN(PAGE_SIZE);

	__init_begin = .;

	/* Will be freed after init */
	__init_text_begin = .;
	INIT_TEXT_SECTION(PAGE_SIZE)
	__init_text_end = .;

	. = ALIGN(PAGE_SIZE);

	__init_data_begin = .;
  	E2K_BOOT_SETUP(16)
	INIT_DATA_SECTION(16)
	PERCPU_SECTION(INTERNODE_CACHE_BYTES)

	. = ALIGN(8);
	.apicdrivers : AT(ADDR(.apicdrivers) - LOAD_OFFSET) {
		__apicdrivers = .;
		*(.apicdrivers);
		__apicdrivers_end = .;
	}

	__init_data_end = .;

	__init_end = .;


	. = ALIGN(E2K_MAX_PAGE_SIZE);	/* Start of data segment */

	_sdata = .;

#ifdef	CONFIG_NUMA
	__node_data_start = .;
		.node.data : { *(.node.data) }
		. = ALIGN(PAGE_SIZE);
	__node_data_end = .;
#endif	/* CONFIG_NUMA */

	EXCEPTION_TABLE(16)

	RW_DATA_SECTION(64, PAGE_SIZE, PAGE_SIZE)

	.got : {
		*(.got)
	}
	.sdata : {
		*(.sdata)
	}
	_edata = .;	/* End of data section */

	BSS_SECTION(0, 0, 0)
	_end = .;

	.mdebug 0 : {
		*(.mdebug)
	}
	.note 0 : {
		*(.note)
	}

	STABS_DEBUG
	DWARF_DEBUG

	DISCARDS
}
