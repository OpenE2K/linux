#ifndef __E2K_A_OUT_H__
#define __E2K_A_OUT_H__

#ifndef __ASSEMBLY__

struct exec {
	unsigned long a_info;	/* Use macros N_MAGIC, etc for access */
	unsigned int a_text;	/* length of text, in bytes */
	unsigned int a_data;	/* length of data, in bytes */

	/* length of uninitialized data area for file, in bytes */
	unsigned int a_bss;

	/* length of symbol table data in file, in bytes */
	unsigned int a_syms;
	unsigned int a_entry;	/* start address */

	/* length of relocation info for text, in bytes */
	unsigned int a_trsize;

	/* length of relocation info for data, in bytes */
	unsigned int a_drsize;
};

#endif /* __ASSEMBLY__ */

#define N_TRSIZE(a)	((a).a_trsize)
#define N_DRSIZE(a)	((a).a_drsize)
#define N_SYMSIZE(a)	((a).a_syms)

#ifdef __KERNEL__

#endif

#endif /* __E2K_A_OUT_H__ */
