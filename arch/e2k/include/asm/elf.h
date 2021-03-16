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
 * e2k relocation types
 */
#define R_E2K_NONE		0
#define R_E2K_32_PC		2
#define R_E2K_64_ABS		50	/* Direct 64 bit */
#define R_E2K_64_ABS_LIT	51	/* Direct 64 bit for LTS syllable */
#define R_E2K_64_CALL		52	/* PC relative 64 bit for DISP */
#define R_E2K_DISP		110	/* PC relative 28-bit for DISP */

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
extern unsigned long vma_dump_size(struct vm_area_struct *vma,
		unsigned long mm_flags);

#endif /* _E2K_ELF_H_ */
