/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/binfmts.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/elfcore.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/elf.h> 
#include <linux/namei.h>
#include <linux/irqflags.h>
#include <linux/sort.h>

#include <asm/process.h>
#include <asm/prot_loader.h>
#include <asm/protected_syscalls.h>

#ifdef	CONFIG_ELF_CORE
extern int elf_core_dump_64(struct coredump_params *cprm);
#else	/* ! CONFIG_ELF_CORE */
#define	elf_core_dump_64	NULL
#endif	/* CONFIG_ELF_CORE */

static int load_e2p_load_binary(struct linux_binprm *);

static struct linux_binfmt elf_format = {
		.module		= THIS_MODULE,
		.load_binary	= load_e2p_load_binary,
		.load_shlib	= NULL,
		.core_dump	= elf_core_dump_64,
		.min_coredump	= ELF_EXEC_PAGESIZE
};

#define BAD_ADDR(x)	((unsigned long)(x) > TASK_SIZE)
#define	check_len(x)	((u64)(x) >= (1L << 32))

#if defined(CONFIG_MMU) && !defined(MAX_ARG_PAGES)
# define MAX_ARG_PAGES	32
#endif

static int protected_elf_code(struct elfhdr *x)
{
	if ((x->e_machine != ELF_ARCH) && (x->e_machine != ELF_ARCH_FAKE)) {
		DBPL("bad ARCH 0x%x != 0x%x\n",  x->e_machine, ELF_ARCH);
		return 0;
	}
	if (x->e_ident[EI_CLASS] != ELF_CLASS) {
		DBPL("bad CLASS 0x%x != 0x%x\n",  x->e_ident[EI_CLASS], ELF_CLASS);
		return 0;
	}

	if (x->e_machine == ELF_ARCH) {
		if ((x->e_flags & ELF_E2K_PM) == 0) {
			DBPL("Protected code expected");
			return 0;
		}
	}
	else if (x->e_machine == ELF_ARCH_FAKE) {
		if (x->e_ident[EI_SEMANTIC] != ELF_CODE_NEW_PROTECTED &&
		    x->e_ident[EI_SEMANTIC] != ELF_CODE_NEW_PROTECTED_CXX) {
			DBPL("bad SEMANTIC: 0x%x != 0x%x and 0x%x != 0x%x\n",
			     x->e_ident[EI_SEMANTIC], ELF_CODE_NEW_PROTECTED,
			     x->e_ident[EI_SEMANTIC], ELF_CODE_NEW_PROTECTED_CXX);
			return 0;
		}
	}

	if (x->e_flags & ELF_BIN_COMP) {
		DBPL("Code for binary compiler not expected");
		return 0;
	}

	if (!elf_check_e2k_mtype(elf_get_e2k_mt(x), IS_INCOMPAT(x))) {
		DBPL("Code for incompatible machine");
		return 0;
	}

	return 1;
}

static unsigned long inline do_mmap_elf(struct file *f,
                         unsigned long addr,
                         unsigned long len,
                         unsigned long prot,
                         unsigned long flags,
                         unsigned long off)
{
	return vm_mmap_notkillable(f, addr, len, prot, flags, off);
}

static inline int do_munmap_elf(unsigned long addr, size_t len)
{
	return vm_munmap_notkillable(addr, len);
}




/*
 *    Layout of arguments for protected task (down to up from stack base) :
 * 	if ( ARGS_AS_ONE_ARRAY) {
 *		descriptior to (4) -(6) area
 *	} else  {
 *		descriptor to (1) - (3) area
 *	 	1. Descriptor to argv descriptors array. 
 *	     		Size of this descriptor = (argc + 1) * sizeof (e2k_ptr_t)
 *	 	2. Descriptor to envp descriptors array.
 *	 	3. Descriptor to the ELF interpreter info.
 *	}
 *	 4. argv descriptors array. Last descriptor is NULL
 *	 5. envp descriptors array. Last descriptor is NULL
 *	 6. ELF interpreter info
 *	 7. argv array
 *	 8. envp array.
 *
 *	(7) and (9) were filled earlier by copy_strings() calls from do_execve
 */


static unsigned long protected_randomize_stack_top(unsigned long stack_top)
{
        unsigned int random_variable = 0;

        if (current->flags & PF_RANDOMIZE)
                random_variable = get_random_int() % (8*1024*1024);
        return PAGE_ALIGN(stack_top - random_variable);
}




/* Let's use some macros to make this stack manipulation a litle clearer */

#define STACK_ALLOC_AUX(sp, items)	\
		(e2k_ptr_t __user *)((u64)((elf_addr_t __user *)(sp) - (items)) & ~15UL)
#define STACK_ALLOC_BYTES(sp, items)	\
		(e2k_ptr_t *)((u64)((char __user *)(sp) - (items)) & ~15UL)
#define STACK_ALLOC_PTRS(sp, len)		(sp - ( len))
#define STACK_ROUND(sp)	\
		(e2k_ptr_t __user *)(((unsigned long) (sp)) & ~15UL)


static int
create_elf_tables(struct linux_binprm *bprm, struct elfhdr *exec,
		unsigned long load_offset, unsigned long start_point,
		unsigned long interp_elfhdr_offset)
{
	unsigned long		p = bprm->p;
	int			argc = bprm->argc;
	int			envc = bprm->envc;
	e2k_ptr_t __user	*sp;
        unsigned long           argcp;
	unsigned long		argvb;
	unsigned long		envpb;
	unsigned long		auxb = 0;
	elf_addr_t		*elf_info = NULL;
	int			ei_index = 0;
#ifdef ARGS_AS_ONE_ARRAY	
	unsigned long	args_end;
#endif
	const struct cred *cred = current_cred();
	/*  was stack aligned accordinatly before? */
	sp = STACK_ROUND(p);
#ifdef ARGS_AS_ONE_ARRAY	
	args_end = (unsigned long)sp;
#endif

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *) current->mm->saved_auxv;
#define NEW_AUX_ENT(id, val) \
	do { elf_info[ei_index++] = id; elf_info[ei_index++] = val; } while (0)

#ifdef ARCH_DLINFO
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHENT, sizeof (struct elf_phdr));
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_UID, from_kuid_munged(cred->user_ns, cred->uid));
	NEW_AUX_ENT(AT_EUID, from_kuid_munged(cred->user_ns, cred->euid));
	NEW_AUX_ENT(AT_GID, from_kgid_munged(cred->user_ns, cred->gid));
	NEW_AUX_ENT(AT_EGID, from_kgid_munged(cred->user_ns, cred->egid));
	NEW_AUX_ENT(AT_SECURE, bprm->secureexec);
	NEW_AUX_ENT(AT_PHDR, load_offset + exec->e_phoff);
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_ENTRY, (u32) start_point);
	NEW_AUX_ENT(AT_BASE, interp_elfhdr_offset);
#if 0
	if (bprm->interp_flags & BINPRM_FLAGS_EXECFD) {
		NEW_AUX_ENT(AT_EXECFD, (elf_addr_t) bprm->interp_data);
	}
#endif
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(&elf_info[ei_index], 0, sizeof (current->mm->saved_auxv) -
			ei_index * sizeof elf_info[0]);
	/* And advance past the AT_NULL entry.  */
	ei_index += 2;

	/* allocate space for ELF interpreter info */
	sp = STACK_ALLOC_AUX(sp, ei_index);
	auxb = (unsigned long)sp;

	/* allocate space for envp descriptors array */
	sp = STACK_ALLOC_PTRS(sp, envc + 1);
	envpb = (unsigned long)sp;

	/* allocate space for argv descriptors arrays */
	sp = STACK_ALLOC_PTRS(sp, argc + 1);
	argvb = (unsigned long)sp;

        /* allocate space for argc at address, aligned to 16 bytes */
        sp = STACK_ALLOC_PTRS(sp, 1);
        argcp = (unsigned long) sp;
	
#ifndef ARGS_AS_ONE_ARRAY	
	/* allocate space for (1) - (3) descriptors */
	sp = STACK_ALLOC_PTRS(sp, 3);
	
#endif

	/* And at last allocate space for base descriptor. */
	sp = STACK_ALLOC_PTRS(sp, 1);

	/* Now sp points to the end of the stack */
	bprm->p = (unsigned long)sp;

	/* Populate allocated areas in revers order */

#ifdef ARGS_AS_ONE_ARRAY
        /* The base descriptor is temporarily saved to the start of the 
           memory area it describes. After it is copied to %qr0 we may
           erase it from stack. */
	if (PUT_USER_AP(sp, bprm->p, args_end - bprm->p, 0L, RW_ENABLE))
		return -EFAULT;
	sp++;
#else
	/* descriptor to the next four ones */
	if (PUT_USER_AP(sp, sp + 1, E2k_ELF_ARG_NUM_AP * sizeof (e2k_ptr_t),
			0L, R_ENABLE))
		return -EFAULT;
	sp++;

	if (PUT_USER_AP(sp + E2k_ELF_ARGV_IND, argvb, (envpb - argvb), 0, R_ENABLE))
		return -EFAULT;
	if (PUT_USER_AP(sp + E2k_ELF_ENVP_IND, envpb, (mddb - envpb), 0, R_ENABLE))
		return -EFAULT;
	if (PUT_USER_AP(sp + E2k_ELF_AUX_IND, auxb,
			(ei_index * sizeof elf_info[0]), 0, R_ENABLE))
		return -EFAULT;
#endif

        /* Save argc. */
	if (clear_user((e2k_ptr_t __user *) argcp, sizeof(e2k_ptr_t)))
		return -EFAULT;

	if (copy_to_user((void __user *) argcp, &argc, sizeof(argc)))
		return -EFAULT;

	/* Populate argv  */
        p = current->mm->arg_end = current->mm->arg_start;
	sp = (e2k_ptr_t __user *)argvb;
	while (argc-- > 0) {
		size_t len;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
			return 0;
		}
		if (PUT_USER_AP(sp++, p, len, 0, RW_ENABLE))
			return -EFAULT;
		p += len;
	}
	if (PUT_USER_AP(sp, 0, 0, 0, 0))
		return -EFAULT;


	/* Populate  envp */
	current->mm->arg_end = current->mm->env_start = p;
	sp = (e2k_ptr_t __user *)envpb;
	while (envc-- > 0) {
		size_t len;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
			return 0;
		}
		if (PUT_USER_AP(sp++, p, len, 0, RW_ENABLE))
			return -EFAULT;
		p += len;
	}
	if (PUT_USER_AP(sp, 0, 0, 0, 0))
		return -EFAULT;
	current->mm->env_end = p;

	/* Put the elf_info on the stack in the right place.  */
	if (copy_to_user((void __user *)auxb, elf_info, ei_index * sizeof(elf_info[0]))) {
		return -EFAULT;
	}

	return 0;
}





static int e2p_consistensy_check(struct file *f, struct elfhdr *elf_ex)
{
	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0) {
		DBPL("elf_ex->e_ident bad\n");
		goto out;
	}
	if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN) {
		DBPL("not ET_EXEC && not ET_DYN\n");
		goto out;
	}
	if (!protected_elf_code(elf_ex)) {
		DBPL("not protected_elf%d_code\n", ELF_CL_SZ);
		goto out;
	}
	if (!f->f_op || !f->f_op->mmap) {
		DBPL("!f->f_op || !f->f_op->mmap\n");
		goto out;
	}
	/* Now read in all of the header information */
	if (elf_ex->e_phentsize != sizeof(struct elf_phdr)) {
		DBPL("elf_ex->e_phentsize(%d) != sizeof(struct elf_phdr)(%ld)\n",
		elf_ex->e_phentsize, sizeof(struct elf_phdr));
		goto out;
	}
	if (elf_ex->e_phnum < 1 ||
		   elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr)) {
		DBPL("elf_ex->e_phnum = %d\n", elf_ex->e_phnum);
		goto out;
	}
	return 0;
out :
	{
		int i; int *p = (int *)elf_ex;
		DBPL("Elf Header :\n");
		for (i = 0; i < sizeof (struct elfhdr) / 4; i += 2) {
			DBPL("   0x%08x  0x%08x\n", p[i], p[i+1]);
		}
	}
	return -ENOEXEC;
}



static int
get_dynamic_data(struct file	*f,
		struct elf_phdr	*phdr_dyn,
		elf_addr_t	*got_off,
		elf_addr_t	*got_sz,
		elf_addr_t	*init_got_entryp,
		elf_addr_t	*init_entryp,
		elf_addr_t	*fini_entryp)
{
	int			retval;
	loff_t			pos;
	elf_dyntab_entry_t	*dyn;
	elf_dyntab_entry_t	*dyn_tofree;
	elf_dyntab_entry_t	*end_dyn;

	if (phdr_dyn->p_filesz % sizeof (elf_dyntab_entry_t)) {
		return -ENOEXEC;
	}
	dyn = (elf_dyntab_entry_t *)kmalloc(phdr_dyn->p_filesz,
							   GFP_KERNEL);
	if (!dyn) {
		return -ENOMEM;
	}
	dyn_tofree = dyn;
	pos = phdr_dyn->p_offset;
	retval = kernel_read(f, dyn, phdr_dyn->p_filesz, &pos);
	if (retval != phdr_dyn->p_filesz) {
		if (retval >= 0) {
			retval = -EIO;
		}
		goto out;
	}
	end_dyn = (elf_dyntab_entry_t *)((char *)dyn + phdr_dyn->p_filesz);

	for ( ; dyn <  end_dyn; dyn++) {
		if (dyn->d_tag == DT_NULL) {
			break;
		}
		switch (dyn->d_tag) {
		case DT_PLTGOT :
			*got_off = dyn->d_un.d_ptr;
			break;
		case DT_PLTGOTSZ :
			*got_sz = dyn->d_un.d_val;
			break;
		case DT_INIT :
			*init_entryp = dyn->d_un.d_ptr;
			break;
		 case DT_INIT_GOT :
			*init_got_entryp = dyn->d_un.d_ptr;
			 break;
		case DT_FINI :
			*fini_entryp = dyn->d_un.d_ptr;
			break;
		default :
			break;
		}
	}
out:
	kfree(dyn_tofree);
	return 0;
}

/* Sort ELF Program Headers in increasing order of their p_vaddrs.
 */
static int elf_phdr_cmp(const void *a, const void *b)
{
	const struct elf_phdr *one = (const struct elf_phdr *) a;
	const struct elf_phdr *two = (const struct elf_phdr *) b;

	return (one->p_vaddr < two->p_vaddr
		? -1 : (one->p_vaddr == two->p_vaddr ? 0 : 1));
}

/**
 *    e2p_load_cu_file_by_headers - loads module into memory.
 *       creates CUT entry for loaded module
 *       initializes mdd if mdd not NULL
 *    Results :
 *       0 if success,  else -errno.
 */
static  int
e2p_load_cu_file_by_headers(struct file *loadf,
			    struct elfhdr *elf,
			    struct elf_phdr *elf_phdr,
			    unsigned long *entryp,
			    kmdd_t *mdd,
			    unsigned long *load_offset,
			    unsigned long *interp_elfhdr_offset)
{
	int		retval = -ENOEXEC;
	unsigned long	ulretval;
	struct elf_phdr	*prog_p;
	int		i;
	unsigned long	start_code_addr = 0;
	unsigned long	start_data_addr = 0;
	elf_addr_t	ud_start = ~0UL;
	elf_addr_t	ud_end  = 0;
	elf_addr_t	ud_allocend = 0L;
	elf_addr_t	ud_mapend  = 0;
	elf_addr_t	uc_start = ~0UL;
	elf_addr_t	uc_end  = 0L;
	elf_addr_t	uc_allocend = 0;
	elf_addr_t	uc_mapend  = 0;
	int		prot;
	unsigned long	start_point = 0;
	unsigned long	init_point = 0;
	unsigned long	fini_point = 0;
	unsigned long	init_got_point = 0;
	struct elf_phdr	*dyn = NULL;
	elf_addr_t	got_off;
	elf_addr_t	got_sz;
	int		tcount = 0;
	elf_addr_t	init_got_entry = 0;
	elf_addr_t	init_entry = 0;
	elf_addr_t	fini_entry = 0;
	int		packed;

	/*
	 * Distinguish between legacy and packed PM ELFs.
	 */
	packed = (elf->e_flags & ELF_E2K_PACK_SEGMENTS) ? 1 : 0;

	/*
	 * In the packed case Program Headers need to be sorted in the
	 * increasing order of their p_vaddrs before being mapped.
	 */
	if (packed)
		sort(elf_phdr, elf->e_phnum, sizeof(elf_phdr[0]),
		     elf_phdr_cmp, NULL);

	/*
	 *    Get the base address and size of image.
	 */
	for ( prog_p = elf_phdr, i  = 0; i < elf->e_phnum; i++,  prog_p++) {
		elf_addr_t start;
		elf_addr_t end;
		elf_addr_t allocend;
		elf_addr_t mapend;

		if (prog_p->p_type == PT_DYNAMIC) {
			dyn = prog_p;
			continue;
		}
		if (prog_p->p_type != PT_LOAD) {
			continue;
		}
		/* case PT_LOAD */
		/* Check the correctness of segment */
		if (prog_p->p_align % PAGE_SIZE != 0) {
			DBPL("load segment not page-aligned 0x%llx.\n",
					 (u64) prog_p->p_align);
			return retval;
		}
		if (!prog_p->p_align) {
			DBPL("load segment alignment is 0\n");
			return retval;
		}
		if (!prog_p->p_align || (prog_p->p_vaddr - prog_p->p_offset) % prog_p->p_align) {
			DBPL("load segment address/offset not properly aligned 0x%llx : 0x%llx.\n",
					(u64) prog_p->p_vaddr, (u64) prog_p->p_offset);
			return retval;
		}
		 /*
		  * Calculate the addresses of data and code segments.
		  */
		if (!(prog_p->p_flags & PF_X)) {
			/*
			 * Handle the data segment
			 */
			start = ud_start;
			end = ud_end;
			allocend = ud_allocend;
			mapend = ud_mapend;
		} else {
			/*
			 * Handle the code segment
			 */
			start = uc_start;
			end = uc_end;
			allocend = uc_allocend;
			mapend = uc_mapend;
		}

		if (!packed) {
			if (start > (prog_p->p_vaddr &
					~(prog_p->p_align - 1))) {
				/* Calculate the start address of the segment
				 * in memory
				 */
				start = prog_p->p_vaddr &
					~(prog_p->p_align - 1);

				/* Save the difference between `p_vaddr' and
				 * `p_offset' of the first data Program Header
				 * containing the Program Headers in  PM ELF.
				 * In `create_elf_tables ()' it will be used to
				 * calculate the Program Headers' runtime
				 * address.
				 */
				if (!(prog_p->p_flags & PF_X) && load_offset)
					*load_offset = (prog_p->p_vaddr
							- prog_p->p_offset);
				if (!(prog_p->p_flags & PF_X)
				    && interp_elfhdr_offset)
					*interp_elfhdr_offset =
						(prog_p->p_vaddr
						 - prog_p->p_offset);
			}
			if (end < prog_p->p_vaddr + prog_p->p_filesz) {
				/* Calculate the end address of data/code
				 * in file.
				 */
				end = prog_p->p_vaddr + prog_p->p_filesz;
			}
			if (allocend < prog_p->p_vaddr + prog_p->p_memsz) {
				/* Calculate the end address of data/code
				 * in memory
				 */
				allocend = prog_p->p_vaddr + prog_p->p_memsz;
			}
			if (mapend < PAGE_ALIGN(prog_p->p_vaddr
						+ prog_p->p_filesz)) {
				/* Calculate the the end address
				 * of mmaped memory
				 */
				mapend = PAGE_ALIGN(prog_p->p_vaddr
						    + prog_p->p_filesz);
			}
		} else /* packed  */ {
			elf_addr_t b, r;

			if (start == ~0UL) {
				/* The first "sorted" segment is mapped
				 * to 0 offset in {CU,G}D.
				 */
				start = 0L;

				/* p_offset (matches p_vaddr) of the first data
				 * segment is mapped to offset (see the
				 * computations below) (p_vaddr & (p_align - 1))
				 * in GD. TODO: to be more strict do NOT rely
				 * on the fact that it's the "first" Program
				 * Header mapped into GD that contains "Program
				 * Headers", but locate such a Program Header
				 * via an explicit
				 * (e_phoff >= p_offset
				 *  && ((e_phoff + e_phnum * e_phentsize)
				 *       <= p_offset + p_filesz)) test instead.
				 * The same can probably be done in legacy case
				 * too.
				 */
				if (!(prog_p->p_flags & PF_X)) {
					unsigned long delta;

					delta = ((prog_p->p_vaddr
						  & (prog_p->p_align - 1))
						 - prog_p->p_offset);

					if (load_offset)
						*load_offset = delta;

					if (interp_elfhdr_offset)
						*interp_elfhdr_offset = delta;
				}
			}

			allocend = PAGE_ALIGN(allocend);
			r = prog_p->p_vaddr & (prog_p->p_align - 1);
			b = ((allocend + prog_p->p_align - (r + 1))
			     / prog_p->p_align);
			/* Let it hold the offset in CUD/GD corresponding to
			 * p_vaddr until it actually becomes "allocend" a few
			 * lines below.
			 */
			allocend = b * prog_p->p_align + r;

			end = allocend + prog_p->p_filesz;
			mapend = PAGE_ALIGN(end);
			allocend = allocend + prog_p->p_memsz;
		}

		if (!(prog_p->p_flags & PF_X)) {
			/*
			 * Handle the data segment
			 */
			ud_start = start;
			ud_end = end;
			ud_allocend = allocend;
			ud_mapend = mapend;
		} else {
			/*
			 * Handle the code segment
			 */
			uc_start = start;
			uc_end = end;
			uc_allocend = allocend;
			uc_mapend = mapend;
		}
	}

	/*
	 * Check if all lenghts and memory offsets no longer than 2**32
	 */

	if (check_len(PAGE_ALIGN(uc_mapend) + PAGE_ALIGN(uc_allocend) -
			PAGE_ALIGN(uc_end))) {
		DBPL("code size too big\n");
		return retval;
	}

	if (check_len(PAGE_ALIGN(ud_mapend) + PAGE_ALIGN(ud_allocend) -
			PAGE_ALIGN(ud_end))) {
		DBPL("data size too big\n");
		return retval;
	}

        /*
	 * Load the module into memory.
	 */
	if (uc_allocend) {
		start_code_addr = do_mmap_elf(NULL, 0, PAGE_ALIGN(uc_allocend),
				PROT_NONE, MAP_PRIVATE | MAP_FIRST32 | MAP_DENYWRITE, 0);
		if (BAD_ADDR(start_code_addr)) {
			retval = (int) (long) start_code_addr;
			return retval;
		}
	}

	if (ud_allocend) {
		start_data_addr = do_mmap_elf(NULL, 0, PAGE_ALIGN(ud_allocend),
				PROT_NONE, MAP_PRIVATE | MAP_FIRST32 | MAP_DENYWRITE, 0);
		if (BAD_ADDR(start_data_addr))
			return (int) (long) start_data_addr;
	}

	if (packed) {
		/* In the packed case these will be reevaluated when
		 * progressively obtaining the "offset" range in CUD/GD
		 * each segment should be mapped to.
		 */
		uc_allocend = 0L;
		ud_allocend = 0L;
	}

	/*
	 * Now search in dynamic section typecount, got offset, got length
	 */
	if (dyn) {
		retval = get_dynamic_data(loadf, dyn, &got_off,
						&got_sz, &init_got_entry,
						&init_entry, &fini_entry);
		if (retval)
			return retval;
		if (check_len(got_sz))
			return -ENOEXEC;
	}

	for ( prog_p = elf_phdr, i  = 0; i < elf->e_phnum; i++,  prog_p++) {
		unsigned mapflag = MAP_PRIVATE | MAP_DENYWRITE | MAP_FIRST32 | MAP_FIXED;
		unsigned long start_aligned, start, end, map_addr;
		unsigned long offset;
		
		if (prog_p->p_type != PT_LOAD) {
			continue;
		}

		prot = 0;

		if (prog_p->p_flags & PF_R)
			prot |= PROT_READ;

                if (prog_p->p_flags & PF_W)
			prot |= PROT_WRITE;


		if (prog_p->p_flags & PF_X)
		{
			prot |= PROT_EXEC;
			mapflag |= MAP_EXECUTABLE;
		}


		if (!packed) {
			/* It's doubtful if the memory in the range [p_vaddr
			 * & ~(p->align - 1), p_vaddr & (PAGE_SIZE - 1)) should
			 * be actually mapped from the file. In other words,
			 * should the segment pages preceding the one
			 * containing p_vaddr be mapped from the file?
			 * Moreover, it's not quite clear if they should be
			 * accessible at all.
			 */
			if (!(prog_p->p_flags & PF_X)) {
				start = start_data_addr + prog_p->p_vaddr;
				start_aligned = (start_data_addr
						 + (prog_p->p_vaddr
						    & ~(prog_p->p_align - 1)));
			}  else {
				start = start_code_addr + prog_p->p_vaddr;
				start_aligned = (start_code_addr
						 + (prog_p->p_vaddr
						    & ~(prog_p->p_align - 1)));
			}

			offset = prog_p->p_offset & ~(prog_p->p_align - 1);
		} else /* packed  */ {
			elf_addr_t allocend;
			elf_addr_t b, r;

			/* The packed implementation believes that the answer
			 * to the above questions is "no" and the only purpose
			 * of p_align is to ensure that the objects in the
			 * containing segment eventually (i.e. at runtime) get
			 * alignments assigned to them during compilation. It
			 * would be funny if my understanding of the role of
			 * p_align turned out to be wrong in the end ...
			 */

			if (!(prog_p->p_flags & PF_X))
				allocend = ud_allocend;
			else
				allocend = uc_allocend;

			allocend = PAGE_ALIGN(allocend);
			r = prog_p->p_vaddr & (prog_p->p_align - 1);
			b = ((allocend + prog_p->p_align - (r + 1))
			     / prog_p->p_align);
			start = b * prog_p->p_align + r;
			allocend = start + prog_p->p_memsz;

			if (!(prog_p->p_flags & PF_X)) {
				start += start_data_addr;
				ud_allocend = allocend;
			} else {
				/* In packed case it's handy to evaluate offsets
				 * in CUD used to set start_point and 3 user
				 * exported PLs in MDD right on seeing the
				 * containing Program Header. FIXME: only
				 * start_point (required to pass execution to
				 * userspace) and init_got_point (exported to
				 * the user) should make sense in packed case
				 * as it implies the use of new (as opposed to
				 * ancient) implementation of uselib.
				 */
				if (elf->e_entry >= prog_p->p_vaddr
				    && elf->e_entry < (prog_p->p_vaddr
						       + prog_p->p_filesz))
					start_point = (start_code_addr
						       + start
						       + elf->e_entry
						       - prog_p->p_vaddr);

				if (init_entry >= prog_p->p_vaddr
				    && init_entry < (prog_p->p_vaddr
						     + prog_p->p_filesz)) {
					init_point = (start_code_addr
						      + start
						      + init_entry
						      - prog_p->p_vaddr);
				}

				if (fini_entry >= prog_p->p_vaddr
				    && fini_entry < (prog_p->p_vaddr
						     + prog_p->p_filesz)) {
					fini_point = (start_code_addr
						      + start
						      + fini_entry
						      - prog_p->p_vaddr);
				}

				if (init_got_entry >= prog_p->p_vaddr
				    && init_got_entry < (prog_p->p_vaddr
							 + prog_p->p_filesz)) {
					init_got_point = (start_code_addr
							  + start
							  + init_got_entry
							  - prog_p->p_vaddr);
				}

				start += start_code_addr;
				uc_allocend = allocend;
			}

			/* According to my believes pages preceding the one
			 * matching p_vaddr should not be accessible.
			 */
			start_aligned = start & ~(PAGE_SIZE - 1);
			offset = prog_p->p_offset & ~(PAGE_SIZE - 1);

		}
		end = PAGE_ALIGN(start + prog_p->p_filesz);
		
		map_addr = do_mmap_elf(loadf, start_aligned,
				       end - start_aligned, prot,
				       mapflag, offset);
		if (map_addr != start_aligned)
			return (int) (long) map_addr;

		if (PAGE_ALIGN(start + prog_p->p_memsz)
		    > start + prog_p->p_filesz ) {
			unsigned long start_zero = start + prog_p->p_filesz;
			unsigned long start_zeropage = PAGE_ALIGN(start_zero );
			unsigned long end_zero =  PAGE_ALIGN(start + prog_p->p_memsz);

			DBPL( "zero start = %#lx, zero end = %#lx, zeropage = %#lx\n",
			      start_zero, end_zero, start_zeropage );

			/* Fill by zeroes the end of the last page with
			 * data from file
			 */
			if (start_zeropage > start_zero) {
				struct vm_area_struct *vma, *prev;
				unsigned long oldflags, newflags;
				struct mm_struct *mm = current->mm;

				/*
				 * The trailing page mapped onto the file may
				 * quite legitimately belong to a readonly
				 * section like `.text' or `.rodata'.
				 * Temporarely make the page writable so as just
				 * to clean up its part mapped beyond `p_offset
				 * + p_filesz', otherwise it will be filled in
				 * with junk data probably from another
				 * section.
				 */
				mmap_write_lock(mm);
				vma = find_vma_prev(mm, start_zeropage - PAGE_SIZE, &prev);
				if (!vma) {
					mmap_write_unlock(mm);
					return -EFAULT;
				}
				oldflags = vma->vm_flags;
				newflags = oldflags | VM_WRITE;
				if (newflags != oldflags &&
				    mprotect_fixup(vma, &prev,
						   start_zeropage - PAGE_SIZE,
						   start_zeropage,
						   newflags) != 0) {
					mmap_write_unlock(mm);
					return -EFAULT;
				}
				mmap_write_unlock(mm);

				if (clear_user((void __user *) start_zero,
						start_zeropage - start_zero))
					return -EFAULT;

				if (newflags != oldflags) {
					mmap_write_lock(mm);
					vma = find_vma_prev(mm, start_zeropage - PAGE_SIZE, &prev);
					if (!vma ||
					    mprotect_fixup(vma, &prev,
							   start_zeropage - PAGE_SIZE,
							   start_zeropage,
							   oldflags) != 0) {
						mmap_write_unlock(mm);
						return -EFAULT;
					}
					mmap_write_unlock(mm);
				}
			}

			/*
			 * Fill by zeroes all the rest pages.
			 */
			if (end_zero > start_zeropage) {
				ulretval = do_mmap_elf(NULL, start_zeropage,
						end_zero - start_zeropage, prot,
						MAP_PRIVATE | MAP_FIRST32 |
							MAP_FIXED | MAP_DENYWRITE,
						0);
				if (ulretval != start_zeropage) {
					DBPL("could not map space for zero pages, "
					     "errno #%d.\n",
					     (int)(-(long)ulretval));
					return (int) (long) ulretval;
				}

				/*
				 * Don't care about defective ELFs with read-
				 * only bss-like sections: let their load fail.
				 */
				if (clear_user((void __user *) start_zeropage,
						end_zero - start_zeropage))
					return -EFAULT;
			}
		}
	}
 	retval = 0;

	/*
	 * everything is mapped. Do some actions to complete the function.
	 */
	if (!packed) {
		if (elf->e_entry) {
			start_point = start_code_addr + elf->e_entry;
			if (start_point >= start_code_addr + uc_end)
				return -ENOEXEC;
		}
	} else {
		/* Start point must have already been "packed" along with the
		 * containing segment. Fail if not.
		 */
		if (start_point == 0)
			return -ENOEXEC;
	}
	
	if (mdd) {
		int cui;
		/* The "packed" values of `{init,{,_got},fini}_point's have
		 * already been evaluated above.
		 */
		if (init_entry && !packed)
			init_point = init_entry + start_code_addr;
		if (fini_entry && !packed)
			fini_point = fini_entry + start_code_addr;
		if (init_got_entry && !packed)
			init_got_point = init_got_entry + start_code_addr;
		DBPL("DBPL : populate mdd (0x%llx, 0x%llx, "
			"0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
			start_data_addr + (u64)got_off, (u64)got_sz,
			init_got_point,  init_point, fini_point, start_point);

		mdd->got_addr = start_data_addr + got_off;
		mdd->got_len = got_sz;
		mdd->init_got_point = init_got_point;
		mdd->init_point = init_point;
		mdd->fini_point = fini_point;
		mdd->entry_point = start_point;

		cui = create_cut_entry(tcount, start_code_addr,
					PAGE_ALIGN(uc_allocend),
					start_data_addr,
					PAGE_ALIGN(ud_allocend));
		if (cui < 0)
			return cui;
		mdd->cui = cui;
	} else {
		DBPL("DBPL : populate current mm\n");
		current->mm->start_code = start_code_addr;
		current->mm->end_code = PAGE_ALIGN(uc_allocend);
		current->mm->start_data = start_data_addr;
		current->mm->end_data = PAGE_ALIGN(ud_allocend);
		current->mm->context.tcount = tcount;
	}

	if (entryp) {
		DBPL("DBPL : start_point = 0x%lx\n", start_point);
		*entryp = start_point;
	}

	/* Ensure that `*load_offset' contains the difference between run-time
	 * address of the first data Program Header and its `p_offset', which
	 * is required to evaluate `AT_PHDR' in `create_elf_tables ()'.
	 */
	if (load_offset)
		*load_offset += start_data_addr;

        return 0;
}

static  int
e2p_load_cu_file(struct file *loadf,
		 struct elfhdr *ret_ehdr,
		 unsigned long *entryp,
		 kmdd_t *mdd,
		 unsigned long *load_offset,
		 unsigned long *interp_elfhdr_offset)
{
	struct elfhdr	ehdr;
	struct elf_phdr	*elf_phdr = NULL;
	unsigned int	size;
	loff_t		pos = 0;
	long		retval = -ENOEXEC;

	
	retval = kernel_read(loadf, &ehdr, sizeof(ehdr), &pos);
	if (retval !=  sizeof(ehdr)) {
		if (retval >= 0)
			retval = -EIO;
		goto out;
	}


	retval = e2p_consistensy_check(loadf, &ehdr);
	if (retval) {
		goto out;
	}

	size = ehdr.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdr = (struct elf_phdr *) kmalloc(size, GFP_KERNEL);
	if (!elf_phdr) {
		goto out;
	}
	pos = ehdr.e_phoff;
	retval = kernel_read(loadf, elf_phdr, size, &pos);
	if (retval != size) {
		if (retval >= 0) {
			retval = -EIO;
		}
		goto out;
	}

	retval = e2p_load_cu_file_by_headers(loadf, &ehdr,
					     elf_phdr, entryp, mdd,
					     load_offset,
					     interp_elfhdr_offset);

	/* If ret_ehdr is non-NULL, this means that the caller wants to replace
	 * the ELF Header of the main executable with that of ld.so
	 */
	if (retval == 0 && ret_ehdr != NULL) {
		*ret_ehdr = ehdr;
	}
out :
	if (elf_phdr) {
		kfree(elf_phdr);
	}
	return retval;
}

static int load_e2p_load_binary(struct linux_binprm * bprm)
{
	struct pt_regs	*regs = current_pt_regs();
	struct elfhdr	elf_ex;
	struct file	*interpf = NULL; /* to shut gcc up */
	char		*interp_name = NULL;
	struct elf_phdr	*elf_ppnt;
	struct elf_phdr	*elf_phdata;
	loff_t		pos;
	int		retval;
	int		i;
	unsigned int	size;
	unsigned long	start_point;
	unsigned long	load_offset = 0;
	long		task_flags = 0;
	unsigned long   interp_elfhdr_offset;

	DBPL("Protected loader elf%d started : %s\n",
		ELF_CL_SZ, bprm->filename);
	/* Get the exec-header */
	elf_ex = *((struct elfhdr *) bprm->buf);
	retval = e2p_consistensy_check(bprm->file, &elf_ex);
	if (retval != 0) {
		DBPL(" PL-elf%d : file %s rejected\n",
			ELF_CL_SZ, bprm->filename);
		goto out;
	}

	size = elf_ex.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdata = (struct elf_phdr *) kmalloc(size, GFP_KERNEL);
	if (!elf_phdata) {
		goto out;
	}
	pos = elf_ex.e_phoff;
	retval = kernel_read(bprm->file, elf_phdata, size, &pos);
	if (retval != size) {
		if (retval >= 0) {
			retval = -EIO;
		}
		goto out_free_ph;
	}
	/* must be here */
	task_flags = current->thread.flags;
	SET_PERSONALITY(elf_ex);


	elf_ppnt = elf_phdata;
	for (i = 0; i < elf_ex.e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type != PT_INTERP) {
			continue;
		}
		retval = -ENOEXEC;
		if (elf_ppnt->p_filesz > PATH_MAX ||
				elf_ppnt->p_filesz < 2) {
			goto out_free_file;
		}
		retval = -ENOMEM;
		interp_name = (char *) kmalloc(
				elf_ppnt->p_filesz, GFP_KERNEL);
		if (interp_name == NULL) {
			goto out_free_file;
		}
		pos = elf_ppnt->p_offset;
		retval = kernel_read(bprm->file, interp_name,
					elf_ppnt->p_filesz, &pos);
		if (retval != elf_ppnt->p_filesz) {
			if (retval >= 0) {
				retval = -EIO;
			}
			goto out_free_interp;
		}
		/* make sure path is NULL terminated */
		retval = -ENOEXEC;
		if (interp_name[elf_ppnt->p_filesz - 1] != '\0') {
			goto out_free_interp;
		}
		interpf = open_exec(interp_name);
		retval = PTR_ERR(interpf);
		if (IS_ERR(interpf)) {
			goto out_free_interp;
		}
		DBPL("PL : use interpreter %s\n", interp_name);
		break;
	}
	
	/* Flush all traces of the currently running executable */
	retval = begin_new_exec(bprm);
	if (retval) {
		goto out_free_interp;
	}

	/* OK, This is the point of no return */
	current->mm->start_data = 0;
	current->mm->end_data = 0;
	current->mm->end_code = 0;
	current->flags &= ~PF_FORKNOEXEC;
	current->mm->def_flags = 0;

	if (elf_read_implies_exec(loc->elf_ex, EXSTACK_DISABLE_X)) {
		current->personality |= READ_IMPLIES_EXEC;
	}
	if ( !(current->personality & ADDR_NO_RANDOMIZE) &&
						randomize_va_space) {
		current->flags |= PF_RANDOMIZE;
	}
	setup_new_exec(bprm);

	retval = setup_arg_pages(bprm, protected_randomize_stack_top(STACK_TOP),
				 EXSTACK_DISABLE_X);
	if (retval < 0)
		goto out_free_interp_file;

	/* load binary or interpreter */
	if (interpf) {
		/* The ELF Header of the main executable is replaced with the
		 * one of the interpreter on return from this function. Note
		 * that it is the latter which should be passed to `create_elf_
		 * tables ()' below.
		 */
		retval = e2p_load_cu_file(interpf, &elf_ex, &start_point, NULL,
					  &load_offset, &interp_elfhdr_offset);
	} else {
		retval = e2p_load_cu_file_by_headers
			(bprm->file,
			 &elf_ex, elf_phdata, &start_point, NULL,
			 &load_offset, &interp_elfhdr_offset);
	}
	if (retval != 0) {
		goto out_free_interp_file;
	}

	set_binfmt(&elf_format);

	/* load data for user */
	retval = create_elf_tables(bprm, &elf_ex, load_offset,
			  /* Entry point should be believed to be unknown if
			   * ld.so is started as an interpreter (or implicitly
			   * in other words).
			   */
			  interpf ? 0 : start_point,
			  interp_elfhdr_offset);
	if (retval)
		goto out_free_interp_file;
	current->mm->start_stack = bprm->p;

	// XXX set stack protection if current->ptrace & PT_PTRACED

	start_thread(regs, start_point, bprm->p);

	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC) {
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		} else {
			send_sig(SIGTRAP, current, 0);
		}
	}
	retval = 0;
	/* Resetting debug mode: */
	current->mm->context.pm_sc_debug_mode = PM_SC_DBG_MODE_DEFAULT;

	/* error cleanup */
out_free_interp_file:
	if (interpf) {
		allow_write_access(interpf);
		fput(interpf);
	}
out_free_interp:
	if (interp_name) {
		kfree(interp_name);
	}
out_free_file:
	if (retval) {
		current->thread.flags = task_flags;
	}
out_free_ph:
	if (elf_phdata) {
		kfree(elf_phdata);
	}
out:
	return retval;
}


long sys_load_cu(const char __user *name, kmdd_t *mdd)
{
	struct file *file;
	struct path path;
	int error;

	error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
	if (error)
		return error;

	if (!S_ISREG(path.dentry->d_inode->i_mode)) {
		path_put(&path);
		return -EACCES;
	}

	error = inode_permission(path.dentry->d_inode, MAY_READ);
	if (error) {
		path_put(&path);
		return error;
	}

	file = dentry_open(&path, O_RDONLY, current_cred());
	path_put(&path);
	if (IS_ERR(file))
		return PTR_ERR(file);

	error = -EACCES;
	if (WARN_ON_ONCE(!S_ISREG(file_inode(file)->i_mode)))
		goto exit;

	error = -ENOEXEC;
	if (file->f_op == NULL)
		goto exit;

	fsnotify_open(file);

	error = e2p_load_cu_file(file, NULL, NULL, mdd, NULL, NULL);
exit:
	fput(file);
	return error;
}

long sys_unload_cu(unsigned long glob_base, size_t glob_size)
{
	int error = 0;
	/*
	 * The information about code segment
	 * of module, which should be unloaded
	 */
	unsigned long code_base;
	size_t code_size;

	if (!glob_base || !glob_size)
		return -EINVAL;

	/* Free cut entry for the module, which should be unloaded */
	error = free_cut_entry(glob_base, PAGE_ALIGN(glob_size),
					&code_base, &code_size);
	if (error)
		return error;

	/* Unmap code and data areas of module */
	error = do_munmap_elf(glob_base, PAGE_ALIGN(glob_size));
	error = do_munmap_elf(code_base, code_size);

	if (error)
		return error;

	return 0;
}

/*   Module load stuff */
static int __init init_elf_binfmt(void)
{
	register_binfmt(&elf_format);

	return 0;
}

static void __exit exit_elf_binfmt(void)
{
	/* Remove the COFF and ELF loaders. */
	unregister_binfmt(&elf_format);
}

core_initcall(init_elf_binfmt);
module_exit(exit_elf_binfmt);

MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");







