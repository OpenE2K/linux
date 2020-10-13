
#include <linux/elfcore-compat.h>
#include <linux/irqflags.h>

typedef		Elf32_Dyn	elf_dyntab_entry_t;
#define		sys_load_cu	sys_load_cu_elf32_3P
#define		ELF_CL_SZ	32

#define	DEBUG_PROTECTED_ELFLOADER	0
#define	DBPL	if (DEBUG_PROTECTED_ELFLOADER) printk

/*
 * Rename the basic ELF layout types to refer to the 32-bit class of files.
 */
#undef	ELF_CLASS
#define ELF_CLASS	ELFCLASS32

#undef	elfhdr
#undef	elf_phdr
#undef	elf_note
#undef	elf_addr_t
#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_note	elf32_note
#define elf_addr_t	Elf32_Addr

/*
 * Rename a few of the symbols that binfmt_elfe2kp.c will define.
 * These are all local so the names don't really matter, but it
 * might make some debugging less confusing not to duplicate them.
 */
#define elf_format		protected_32_elf_format
#define init_elf_binfmt		init_protected_32_elf_binfmt
#define exit_elf_binfmt		exit_protected_32_elf_binfmt

#include "./binfmt_elfe2kp.c"

