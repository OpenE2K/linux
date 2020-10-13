
#include <linux/elf.h> 

typedef		Elf64_Dyn	elf_dyntab_entry_t;
#define		sys_load_cu	sys_load_cu_elf64_3P
#define		ELF_CL_SZ	64


#define	DEBUG_PROTECTED_ELFLOADER	0
#define	DBPL	if (DEBUG_PROTECTED_ELFLOADER) printk

#define elf_format		protected_64_elf_format
#define init_elf_binfmt		init_protected_64_elf_binfmt
#define exit_elf_binfmt		exit_protected_64_elf_binfmt

#include "./binfmt_elfe2kp.c"

