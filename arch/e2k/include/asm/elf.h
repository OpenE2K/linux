#ifndef _E2K_ELF_H_
#define _E2K_ELF_H_

/*
 * ELF register definitions..
 */

#include <asm/auxvec.h>
#include <asm/ptrace.h>
#include <asm/e2k_api.h>
#include <asm/user.h>


#define PT_E2K_TAGS	0x70000000

/*
 * These are used to set parameters in the core dumps.
 */
#define ELF_ARCH_FAKE	EM_E2K_FAKE
#define ELF_ARCH	EM_E2K
#define ELF_CLASS	ELFCLASS64
#define ELF_DATA	ELFDATA2LSB

//  #define CORE_DUMP_USE_REGSET !!!!

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */

#define elf_check_arch(x)						\
	( (((x)->e_machine == ELF_ARCH &&				\
	   ((x)->e_flags & ELF_E2K_PM) == 0) ||				\
	  ((x)->e_machine == ELF_ARCH_FAKE &&				\
	   (x)->e_ident[EI_SEMANTIC] == ELF_CODE_64_UNPROTECTED)) &&	\
           (x)->e_ident[EI_CLASS] == ELFCLASS64 &&			\
	   elf_check_e2k_mtype(x)					\
	)

#define compat_elf_check_arch(x)					\
	( (((x)->e_machine == ELF_ARCH &&				\
	   ((x)->e_flags & ELF_E2K_PM) == 0) ||				\
	  ((x)->e_machine == ELF_ARCH_FAKE &&				\
	   (x)->e_ident[EI_SEMANTIC] == ELF_CODE_32_UNPROTECTED)) &&	\
           (x)->e_ident[EI_CLASS] == ELFCLASS32 &&			\
	   elf_check_e2k_mtype(x)					\
	)

/* General registers */

typedef unsigned long long elf_greg_t;

typedef struct user_regs_struct elf_gregset_t;

/* Floating point registers */

/*
 * NEEDSWORK: Take care about floating point registers too!
 */

/* just to get the things compiled */
#define ELF_NFPREG	32

typedef double elf_fpreg_t;
typedef elf_fpreg_t elf_fpregset_t[ELF_NFPREG];

/* Addition types of symbol type. */

#define STT_PRIVATE      5
#define STT_INIT_FUNC    6
#define STT_FINI_FUNC    7

#define USE_ELF_CORE_DUMP
#define ELF_EXEC_PAGESIZE       4096
//#define CORE_DUMP_USE_REGSET

#ifdef __KERNEL__
/* #define ELF_CORE_COPY_REGS(gregs, regs) \
	memcpy(gregs, regs, sizeof(struct pt_regs)); */

/* regs is struct pt_regs, pr_reg is elf_gregset_t (which is
   now struct_user_regs, they are different) */

#define ELF_CORE_COPY_REGS(pr_reg, regs) \
	core_pt_regs_to_user_regs(regs, (struct user_regs_struct*) (&pr_reg));
extern void core_pt_regs_to_user_regs (struct pt_regs *pt_regs,
				  struct user_regs_struct *user_regs);
#endif /* __KERNEL__ */
	
/* This yields a mask that user programs can use to figure out what
   instruction set this cpu supports.  This could be done in userspace,
   but it's not easy, and we've already done it here.  */

#define ELF_HWCAP	(0)

/* This yields a string that ld.so will use to load implementation
   specific libraries for optimization.  This is more specific in
   intent than poking at uname or /proc/cpuinfo.

   For the moment, we have only optimizations for the Intel generations,
   but that could change... */

#define ELF_PLATFORM	(NULL)

/* This is the location that an ET_DYN program is loaded if exec'ed.  Typical
   use of this is to invoke "./ld.so someprog" to test out a new version of
   the loader.  We need to make sure that it is out of the way of the program
   that it will "exec", and that there is sufficient room for the brk.  */

#define ELF_ET_DYN_BASE         (2 * TASK_SIZE / 3)	/* NEEDSWORK */
#define COMPAT_ELF_ET_DYN_BASE	(2 * TASK32_SIZE / 3)

#ifdef __KERNEL__
#define SET_PERSONALITY(ex)			        		\
do {									\
	current->thread.flags &= ~E2K_FLAG_64BIT_BINCO;			\
	if (((ex).e_machine == ELF_ARCH &&				\
	     ((ex).e_flags & ELF_E2K_PM)) ||				\
	    ((ex).e_machine == ELF_ARCH_FAKE &&				\
	     ((ex).e_ident[EI_SEMANTIC] == ELF_CODE_NEW_PROTECTED ||	\
	      (ex).e_ident[EI_SEMANTIC] == ELF_CODE_NEW_PROTECTED_CXX))) { \
		current->thread.flags |= E2K_FLAG_PROTECTED_MODE;	\
		if ((ex).e_ident[EI_CLASS] == ELFCLASS32) {		\
			current->thread.flags |= E2K_FLAG_3P_ELF32;	\
		} else {						\
			current->thread.flags &= ~ E2K_FLAG_3P_ELF32;	\
		}							\
	} else	{							\
		current->thread.flags &= ~(E2K_FLAG_PROTECTED_MODE |	\
                                           E2K_FLAG_3P_ELF32);          \
	}								\
	if ((ex).e_ident[EI_CLASS] == ELFCLASS32)                       \
		current->thread.flags |= E2K_FLAG_32BIT;                \
	else                                                            \
		current->thread.flags &= ~E2K_FLAG_32BIT;               \
	if ((ex).e_flags & ELF_BIN_COMP)                               \
		current->thread.flags |= E2K_FLAG_BIN_COMP_CODE;        \
	else                                                            \
		current->thread.flags &= ~E2K_FLAG_BIN_COMP_CODE;       \
} while (0)
#endif

#define FAST_SYSCALLS_ENTRY 0x1f
/*
 * SYSTEM_INFO_ENTRY:
 * 0x1: vfork() supported
 */
#define SYSTEM_INFO_ENTRY 0x1
#define	E2K_DLINFO							\
do {									\
	NEW_AUX_ENT(AT_FAST_SYSCALLS, FAST_SYSCALLS_ENTRY);		\
	NEW_AUX_ENT(AT_SYSTEM_INFO, SYSTEM_INFO_ENTRY);			\
} while (0)

#define ARCH_DLINFO		E2K_DLINFO
#define COMPAT_ARCH_DLINFO	E2K_DLINFO


/*
 * Support for tags dumping
 */
#define ELF_CORE_EXTRA_PHDRS	(current->mm->map_count)

#define ELF_CORE_WRITE_EXTRA_PHDRS \
do { \
	for (vma = first_vma(current, gate_vma); vma != NULL; \
			vma = next_vma(vma, gate_vma)) { \
		struct elf_phdr phdr; \
 \
		phdr.p_type = PT_E2K_TAGS; \
		phdr.p_offset = offset; \
		phdr.p_vaddr = vma->vm_start; \
		phdr.p_paddr = 0; \
		phdr.p_filesz = vma_dump_size(vma, mm_flags) / 16; \
		phdr.p_memsz = 0; \
		offset += phdr.p_filesz; \
		phdr.p_flags = 0; \
		phdr.p_align = 1; \
 \
		DUMP_WRITE(&phdr, sizeof(phdr)); \
	} \
} while (0)

#define ELF_CORE_WRITE_EXTRA_DATA \
do { \
	for (vma = first_vma(current, gate_vma); vma != NULL; \
			vma = next_vma(vma, gate_vma)) { \
		unsigned long addr; \
		unsigned long end; \
 \
		end = vma->vm_start + vma_dump_size(vma, mm_flags); \
 \
		for (addr = vma->vm_start; addr < end; addr += PAGE_SIZE) { \
			struct page *page; \
			int stop = 0; \
 \
			page = get_dump_page(addr); \
			if (page) { \
				/* 2 bytes of tags correspond \
				 * to 32 bytes of data */ \
				u16 tags[PAGE_SIZE / 32]; \
				void *kaddr = kmap(page); \
				int i; \
				prefetchw_range(kaddr, PAGE_SIZE); \
				for (i = 0; i < PAGE_SIZE / 32; i++) \
					E2K_EXTRACT_TAGS_32(&tags[i], \
							kaddr + 32 * i); \
				stop = ((size += sizeof(tags)) > cprm->limit) \
					|| !dump_write(cprm->file, tags, \
						       sizeof(tags)); \
				kunmap(page); \
				page_cache_release(page); \
			} else { \
				/* The last pages of CUT are not allocated \
				 * and they might be skipped in tags section \
				 * of core file, so we have to write the very \
				 * last page to make sure that core file size \
				 * is the same as declared in ELF headers. */ \
				if (addr == end - PAGE_SIZE) { \
					stop = !dump_write(cprm->file, \
						(void *)empty_zero_page, \
						PAGE_SIZE / 16); \
				} else { \
					dump_seek(cprm->file, PAGE_SIZE / 16); \
				} \
			} \
			if (stop) \
				goto end_coredump; \
		} \
	} \
} while (0)

#endif /* _E2K_ELF_H_ */
