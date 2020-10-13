#include <linux/binfmts.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/personality.h>
#include <linux/elfcore.h>
#include <linux/security.h>
#include <linux/random.h>
#include <linux/elf.h> 
#include <linux/namei.h>
#include <linux/irqflags.h>

#include <asm/process.h>
#include <asm/prot_loader.h>

extern int elf_core_dump_64(struct coredump_params *cprm);
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

static int protected_elf_code( struct elfhdr * x)
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

	if (x->e_flags & ELF_BIN_COMP)
	{
		DBPL("Code for binary compiler not expected");
		return 0;
	}

	if (!elf_check_e2k_mtype(x))
	{
		DBPL("Code for incompatible machine");
		return 0;
	}

	return 1;
}

static unsigned int inline do_mmap_elf(struct file *f,
                         unsigned long addr,
                         unsigned long len,
                         unsigned long prot,
                         unsigned long flags,
                         unsigned long off)
{
	return vm_mmap(f, addr, len,prot, flags, off);
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


static unsigned long randomize_stack_top(unsigned long stack_top)
{
        unsigned int random_variable = 0;

        if (current->flags & PF_RANDOMIZE)
                random_variable = get_random_int() % (8*1024*1024);
        return PAGE_ALIGN(stack_top - random_variable);
}




/* Let's use some macros to make this stack manipulation a litle clearer */

#define STACK_ALLOC_AUX(sp, items)	\
		(e2k_ptr_t *)((u64)((u32  *)(sp) - (items)) &~ 15UL)
#define STACK_ALLOC_BYTES(sp, items)	\
		(e2k_ptr_t *)((u64)((char __user *)(sp) - (items)) &~ 15UL)
#define STACK_ALLOC_PTRS(sp, len)		(sp - ( len))
#define STACK_ROUND(sp)	\
		(e2k_ptr_t *)(((unsigned long) (sp)) &~ 15UL)


static int
create_elf_tables(struct linux_binprm *bprm)
{
	unsigned long		p = bprm->p;
	int			argc = bprm->argc;
	int			envc = bprm->envc;
	e2k_ptr_t 		*sp;
        unsigned long           argcp;
	unsigned long		argvb;
	unsigned long		envpb;
	unsigned long		auxb = 0;
	u32			*elf_info = NULL;
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
	elf_info = (u32 *) current->mm->saved_auxv;
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
	NEW_AUX_ENT(AT_SECURE, (u32)security_bprm_secureexec(bprm));
#if 0
	NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_ENTRY, exec->e_entry);
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
	sp = STACK_ALLOC_AUX(p, ei_index);
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
	PUT_USER_AP(sp, bprm->p, args_end - bprm->p, 0L, R_ENABLE);
	sp++;
#else
	/* descriptor to the next four ones */
	PUT_USER_AP(sp, sp + 1, E2k_ELF_ARG_NUM_AP * sizeof (e2k_ptr_t),
			0L, R_ENABLE);
	sp++;

	PUT_USER_AP(sp + E2k_ELF_ARGV_IND, argvb,
		    (envpb - argvb), 0, R_ENABLE);
	PUT_USER_AP(sp + E2k_ELF_ENVP_IND, envpb,
		     (mddb - envpb), 0, R_ENABLE);
	PUT_USER_AP(sp + E2k_ELF_AUX_IND, auxb,
		     (ei_index * sizeof elf_info[0]), 0, R_ENABLE);
	}
#endif

        /* Save argc. */
        clear_user((e2k_ptr_t __user *) argcp, sizeof(e2k_ptr_t));
        copy_to_user((void __user *) argcp, &argc, sizeof(argc));

		
	/* Populate argv  */
        p = current->mm->arg_end = current->mm->arg_start;
	sp = (e2k_ptr_t __user *)argvb;
	while (argc-- > 0) {
		size_t len;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
			return 0;
		}
		PUT_USER_AP(sp++, p, len, 0, RW_ENABLE);
		p += len;
	}
	PUT_USER_AP(sp, 0, 0, 0, 0);


	/* Populate  envp */
	current->mm->arg_end = current->mm->env_start = p;
	sp = (e2k_ptr_t __user *)envpb;
	while (envc-- > 0) {
		size_t len;
		len = strnlen_user((void __user *)p, PAGE_SIZE*MAX_ARG_PAGES);
		if (!len || len > PAGE_SIZE*MAX_ARG_PAGES) {
			return 0;
		}
		PUT_USER_AP(sp++, p, len, 0, RW_ENABLE);
		p += len;
	}
	PUT_USER_AP(sp, 0, 0, 0, 0);
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
get_dynamic_data(struct file		*f,
                 struct elf_phdr	*phdr_dyn,
                 elf_addr_t		*got_off,
                 elf_addr_t		*got_sz,
                 int                    *tcount,
                 elf_addr_t             *init_got_entryp,
                 elf_addr_t		*init_entryp,
                 elf_addr_t             *fini_entryp,
                 elf_addr_t             *dst_gtt_off,
                 elf_addr_t             *dst_gtt_sz)
{
	int					retval;
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
	retval = kernel_read(f, phdr_dyn->p_offset,
				(char *)dyn, phdr_dyn->p_filesz);
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
		case DT_TCT :
			*tcount = dyn->d_un.d_val;
			break;
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
                case DT_GOTT:
                case DT_GCTT:
                case DT_GOMPT:
                        /* Смещение одной из секций .gott, .gctt и .gompt в сегменте
                           данных. */
                        dst_gtt_off[dyn->d_tag - DT_GOTT] = dyn->d_un.d_ptr;
                        break;
                case DT_GOTTSZ:
                case DT_GCTTSZ:
                case DT_GOMPTSZ:
                        /* Размер соответствующей секции. */
                        dst_gtt_sz[dyn->d_tag - DT_GOTTSZ] = dyn->d_un.d_val;
                        break;
		default :
			break;
		}
	}
out:
	kfree(dyn_tofree);
	return 0;
}



/* Вспомогательная функция. Приделывает внешние тэги (tag) к двойному слову (val) и
   помещает сформированный дескриптор в dst. Возможно, ее место совсем не здесь. */

static void
emit_tagged_dword(char *dst, unsigned long val, unsigned long tag)
{
        unsigned long ap_lo, ap_hi;

	ap_lo = MAKE_AP_LO((unsigned long) dst, 0x08UL, 0, RW_ENABLE);
	ap_hi = MAKE_AP_HI((unsigned long) dst, 0x08UL, 0, RW_ENABLE);

	asm volatile (  "addd  \t0x0, %0, %%db[2]\n\t" 
			"addd  \t0x0, %1, %%db[4]\n\t"
			"addd  \t0x0, %2, %%db[5]\n\t"
			"puttagd \t%%db[2], %5, %%db[2]\n\t"
			"puttagd \t%%db[4], %3 , %%db[4]\n\t"
			"puttagd \t%%db[5], %4 , %%db[5]\n\t"
			"{ stapd \t%%qb[4], 0x0, %%db[2]\n\t }"
                        : 
                        : "r" (val), "r" (ap_lo), "r" (ap_hi),
                          "i" (E2K_AP_LO_ETAG), "i" (E2K_AP_HI_ETAG), "r" (tag)
                        : "%b[2]", "%b[4]", "%b[5]");  
}


/* Вспомогательная функция. Приделывает внешние тэги (lo_tag, hi_tag) к квадро слову
   (lo_val, hi_val) и помещает сформированный дескриптор в dst. Возможно, ее место
   совсем не здесь. */

static void
emit_tagged_qword(char *dst, unsigned long lo_val, unsigned long lo_tag, unsigned long hi_val, unsigned long hi_tag)
{
        unsigned long ap_lo, ap_hi;

	ap_lo = MAKE_AP_LO((unsigned long) dst, 0x10UL, 0, RW_ENABLE);
	ap_hi = MAKE_AP_HI((unsigned long) dst, 0x10UL, 0, RW_ENABLE);

	asm volatile (  "addd  \t0x0, %0, %%db[2]\n\t"  /* Здесь мы кладем в регистры младшую и старшую части */
                        "addd  \t0x0, %1, %%db[3]\n\t"  /* записываемого значения. */
                        
			"addd  \t0x0, %2, %%db[4]\n\t"  /* Здесь на регистры кладется заготовка для дескриптора, описывающего */
			"addd  \t0x0, %3, %%db[5]\n\t"  /* область памяти, в которой будет сформировано тэгированное значение. */

			"puttagd \t%%db[2], %6, %%db[2]\n\t"    /* Формируем тэгированное значение. */
                        "puttagd \t%%db[3], %7, %%db[3]\n\t"    /* с заданными тэгами. */

			"puttagd \t%%db[4], %4 , %%db[4]\n\t"   /* Заканчиваем формирование дескриптора области памяти, в которой */
			"puttagd \t%%db[5], %5 , %%db[5]\n\t"   /* формируется тэгированное значение: устанавливаем тэги. */

			"{ stapq \t%%qb[4], 0x0, %%qb[2]\n\t }" /* Помещаем сформированное тэгированное значение в память. */
                        : 
                        : "r" (lo_val), "r" (hi_val), "r" (ap_lo), "r" (ap_hi),
                          "i" (E2K_AP_LO_ETAG), "i" (E2K_AP_HI_ETAG), "r" (lo_tag), "r" (hi_tag)
                        : "%b[2]", "%b[3]", "%b[4]", "%b[5]");  
}


/* Функция заполняет соответствующую секцию модуля (dst) следующими тэгированными значениями: 
   Object Template (type == 0, размер дескриптора - квадро слово),
   Cast Template (type == 1, размер дескриптора - квадро слово),
   Object Member Pointer (type == 2, размер дескриптора - двойное слово).
   В качестве заготовок (без внешних тэгов) используются значения, сформированные пользовательским
   загрузчиком в src. */

static int
fill_gtt_section(unsigned type, char *dst, const char *src, elf_addr_t sz)
{
        /* Маски для вырезания внутренних тэгов. */
        static unsigned long itag_mask[3] = {0xe000000000000000, 0xe000000000000000, 0x4000000000000000};
        /* Значения, которые должны получиться при наложении масок в зависимости от типа дескриптора
           (type). Используются для проверки корректности внутренних тэгов, сформированных
           пользовательским загрузчиком. */
        static unsigned long itag_prv[3] =  {0x6000000000000000, 0x4000000000000000, 0x4000000000000000};

        elf_addr_t descr_sz = (type < 2) ? 16 : 8;
        char *start_dst = dst;


#if 0
        assert(type < 3);
#endif /* 0 */      

         /* Размер секции должен быть кратен размеру дескриптора. */
        if (sz % descr_sz != 0)
        {
                DBPL("Wrong .gtt (#%u) section size == %u\n", type, (unsigned) sz);
                return -ENOEXEC;
        }


        for (; dst < start_dst + sz; src += descr_sz, dst += descr_sz)
        {
                /* Проверяем внутренние тэги, установленные пользовательским загрузчиком
                   в младшем двойном слове заготовки. */
                if (((*((unsigned long *) src)) & itag_mask[type]) != itag_prv[type])
                        return -ENOEXEC;
                if (type < 2)
                        emit_tagged_qword (dst, * (unsigned long *) src, 0xf, * (unsigned long *) (src + 8), 0xf);
                else
                        emit_tagged_dword (dst, *(unsigned long *) src, 0xa);
        }

        return 0;
}



/**
 *    e2p_load_cu_file_by_headers - Загружает модуль в память.
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
					  kmdd_t *mdd)
{
	int		retval = -ENOEXEC;
	unsigned long	ulretval;
	struct elf_phdr	*prog_p;
	int		i;
	unsigned 		mapflag;
	unsigned		startaddr;
	elf_addr_t		ud_start = ~0;
	elf_addr_t		ud_end  = 0;
	elf_addr_t		ud_allocend  = 0L;
	elf_addr_t		ud_mapend  = 0;
	elf_addr_t		ud_mapoff  = ~0;
	int				ud_prot = 0;
	elf_addr_t 		uc_start = ~0;
	elf_addr_t		uc_end  = 0L;
	elf_addr_t		uc_allocend  = 0;
	elf_addr_t		uc_mapend  = 0;
	elf_addr_t		uc_mapoff  = ~0;
	int				uc_prot = PROT_EXEC;
	unsigned		uc_size = 0;
	unsigned		ud_size = 0;
	unsigned long	u_code = ~0UL;
	unsigned long	u_data = 0UL;
	unsigned long	start_point = 0;
	unsigned long	init_point = 0;
	unsigned long	fini_point = 0;
	 unsigned long	 init_got_point = 0;
	struct elf_phdr	*dyn = NULL;
	elf_addr_t		got_off;
	elf_addr_t		got_sz;
        elf_addr_t              dst_gtt_off[3] = {0, 0, 0};
        elf_addr_t              dst_gtt_sz[3] = {0, 0, 0};
	int                     tcount = 0;
	elf_addr_t		init_got_entry = 0;
	elf_addr_t		init_entry = 0;
	elf_addr_t		 fini_entry = 0;
	elf_addr_t		dp_off = 0;
	/*
	 *    Получение базового адреса и размера образа.
	  */
	for ( prog_p = elf_phdr, i  = 0; i < elf->e_phnum; i++,  prog_p++) {
		if (prog_p->p_type == PT_DYNAMIC) {
			dyn = prog_p;
			continue;
		}
		if (prog_p->p_type != PT_LOAD) {
			continue;
		}
		/* case PT_LOAD */
		 /*
		  * Проверка корректности сегмента.
		  */
		if ( prog_p->p_align % PAGE_SIZE != 0 ) {
			DBPL("load segment not page-aligned 0x%lx.\n",
				 (u64) prog_p->p_align);
			goto out;
		}
		 if ((prog_p->p_vaddr - prog_p->p_offset) % prog_p->p_align ) {
			DBPL( "load segment address/offset not properly"
				" aligned 0x%lx : 0x%lx.\n",
				(u64)prog_p->p_vaddr, (u64)prog_p->p_offset);
			goto out;
		}
		 /*
		  * Вычисление сегментов кода и данных.
		  */
		 if (prog_p->p_flags & PF_W ) {
			 /*
			  * Обработка сегмента данных.
			  */
			 if (ud_start > (prog_p->p_vaddr &
						 ~(prog_p->p_align - 1))) {
				 /* Определение начального адреса данных
				  */
				ud_start = prog_p->p_vaddr &
						 ~(prog_p->p_align - 1);
			}
			if (ud_end < prog_p->p_vaddr + prog_p->p_filesz) {
				 /* Определение конечного адреса
				  файловых данных */
				ud_end = prog_p->p_vaddr + prog_p->p_filesz;
			}
			 if (ud_allocend < prog_p->p_vaddr +
						 prog_p->p_memsz) {
				 /* Определение конечного адреса всех
				     данных */
				ud_allocend = prog_p->p_vaddr +
							 prog_p->p_memsz;
			}
			if (ud_mapend < PAGE_ALIGN(prog_p->p_vaddr +
							 prog_p->p_filesz)) {
				/* Определение конечного адреса
				   отмапированной памяти */
				ud_mapend = PAGE_ALIGN(prog_p->p_vaddr
						 + prog_p->p_filesz);
			}
		 	if (ud_mapoff > (prog_p->p_offset &
						 ~(prog_p->p_align - 1))) {
				 /* Определение начального смещения
				     данных на файле */
				ud_mapoff = prog_p->p_offset &
						 ~(prog_p->p_align - 1);
				dp_off = prog_p->p_offset;
			}
			ud_prot |= PROT_WRITE;
			if (prog_p->p_flags & PF_R) {
				ud_prot |= PROT_READ;
			}
			if (prog_p->p_flags & PF_X) {
				ud_prot |= PROT_EXEC;
			}
		}  else {
			/*
			 * Обработка сегмента кода.
			  */
			if (uc_start > (prog_p->p_vaddr &
						 ~(prog_p->p_align - 1))) {
				/* Определение начального адреса кода */
				uc_start = prog_p->p_vaddr &
						 ~(prog_p->p_align - 1);
			}
			if (uc_end < prog_p->p_vaddr + prog_p->p_filesz) {
				 /* Определение конечного адреса
				     файловых данных */
				uc_end = prog_p->p_vaddr + prog_p->p_filesz;
			}
			 if (uc_allocend < prog_p->p_vaddr +
						 prog_p->p_memsz) {
				/* Определение конечного адреса всех
				    данных */
				uc_allocend = prog_p->p_vaddr +
						 prog_p->p_memsz;
			}
			 if (uc_mapend < PAGE_ALIGN(prog_p->p_vaddr +
					 prog_p->p_filesz)) {
				 /* Определение конечного адреса
				      отмапированной памяти */
				uc_mapend = PAGE_ALIGN(prog_p->p_vaddr +
						 prog_p->p_filesz);
			}
			if (uc_mapoff >
				 (prog_p->p_offset & ~(prog_p->p_align - 1))) {
				/* Определение начального смещения кода
				 * на файле
				 */
				uc_mapoff = prog_p->p_offset &
						 ~(prog_p->p_align - 1);
			}
			if (prog_p->p_flags & PF_R) {
				uc_prot |= PROT_READ;
			}
			if (prog_p->p_flags & PF_W) {
				uc_prot |= PROT_WRITE;
			}
			if (prog_p->p_flags & PF_X) {
				uc_prot |= PROT_EXEC;
			}
		}
	}

	DBPL( "# Code segment: start  = %lx, dataend = %lx,"
		" allocend = %lx\n",
		(u64)uc_start, (u64)uc_end,(u64) uc_allocend );
	DBPL( "#               mapend = %lx,  mapoff = %lx,  protect = %lx\n",
		(u64)uc_mapend, (u64)uc_mapoff, (u64)uc_prot );
	DBPL( "# Data segment: start  = %lx, dataend = %lx,"
		" allocend = %lx\n",
		(u64)ud_start, (u64)ud_end, (u64)ud_allocend );
	DBPL( "#               mapend = %lx,  mapoff = %lx(%lx),"
		"  protect = %lx\n",
		(u64)ud_mapend, (u64)ud_mapoff,(u64) dp_off, (u64)ud_prot );

	/*
	  *    Загрузка модуля в память.
	 */
	startaddr = PAGE_SIZE;
	mapflag = MAP_PRIVATE | MAP_FIRST32;

	/* check if all lenghts and memory offsets no longer than 2**32  */

	retval = -ENOEXEC;

	if (check_len(PAGE_ALIGN(uc_mapend) + PAGE_ALIGN(uc_allocend) -
			PAGE_ALIGN(uc_end))) {
		DBPL("code size too big\n");
		goto out;
	}
	if (check_len(PAGE_ALIGN(ud_mapend) + PAGE_ALIGN(ud_allocend) -
			PAGE_ALIGN(ud_end))) {
		DBPL("data size too big\n");
		goto out;
	}
	 /*
	  * Мапирование сегмента кода.
	 */
	uc_prot |= PROT_EXEC;
	mapflag = MAP_PRIVATE | MAP_FIRST32 | MAP_EXECUTABLE;
	 if (uc_start < uc_mapend) {
		if (uc_start ) {
			//  XXX can it really be?
			u_code = do_mmap_elf(NULL, startaddr, uc_start,
					uc_prot,
					mapflag,
					0);
			if (BAD_ADDR(u_code)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long) u_code));
					retval = u_code;
					goto out;
			}
			uc_size = uc_start;
			ulretval =  do_mmap_elf(loadf, u_code + uc_start,
					uc_mapend - uc_start,
					uc_prot,
					mapflag | MAP_FIXED,
					uc_mapoff);
			if (BAD_ADDR(ulretval)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long)ulretval));
					retval = ulretval;
					goto out;
			}
			uc_size += uc_mapend - uc_start;
		} else {
			u_code = do_mmap_elf(loadf, startaddr,
					uc_mapend,
					uc_prot | PROT_EXEC,
					mapflag,
					uc_mapoff);
			if (BAD_ADDR(u_code)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long)u_code));
				retval = u_code;
				goto out;
			}
			uc_size = uc_mapend;
		}
		DBPL( "# Code segment: %lx\n", u_code );
	}

	 /*
	  * Обнуление данных сегмента после данных кода,
	 *  отмапированных из файла.
	 */
	 if (uc_allocend > uc_end ) {
		unsigned long start_zero = u_code + uc_end;
		unsigned long end_zero =  PAGE_ALIGN(u_code + uc_allocend);
		unsigned long start_zeropage = PAGE_ALIGN(start_zero );

		DBPL( "zero start = %#lx, zero end = %#lx, zeropage = %#lx\n",
				 start_zero, end_zero, start_zeropage );
		if (start_zeropage > end_zero) {
			 /* Все дополнительные данные находятся
			 *  на одной странице сегмента.
			 */
			start_zeropage = end_zero;
		}

		/*
		  * Обнуление заключительной части последней страницы
		 * с данными из файла.
		  */
		if (start_zeropage > start_zero ) {
			clear_user( (void*)start_zero, start_zeropage - start_zero );
		}

		 /*
		  * Обнуление остальных страниц.
		 */
		 if (end_zero > start_zeropage) {
			ulretval = do_mmap_elf(NULL, start_zeropage,
					end_zero - start_zeropage,
					uc_prot ,
					mapflag | MAP_FIXED,
					0);
			if (BAD_ADDR(u_code)) {
				DBPL("could not map space for zero pages, "
					"errno #%d.\n",
					(int)(-(long)ulretval));
				retval = (int)(long)ulretval;
				goto out;
			}
		}
		uc_size = PAGE_ALIGN(uc_allocend);
	} else {
		uc_size = PAGE_ALIGN(uc_end);
	}

	/*
	 * Мапирование сегмента данных.
	 */
	mapflag = MAP_PRIVATE | MAP_FIRST32;
	 if (ud_start < ud_mapend ) {
		if (ud_start) {
			u_data = do_mmap_elf(NULL, 0L, ud_start,
						ud_prot,
						mapflag,
						0);
			if (BAD_ADDR(u_data)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long) u_data));
					retval = u_data;
					goto out;
			}
			ud_size = ud_start;
			ulretval = do_mmap_elf(loadf, u_data + ud_start,
						ud_mapend - ud_start,
						ud_prot,
						mapflag | MAP_FIXED,
						ud_mapoff);
			if (BAD_ADDR(ulretval)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long)ulretval));
					retval = ulretval;
					ud_size = ud_start;
					goto out;
			}
			ud_size += ud_mapend - ud_start;
		}   else {
			u_data = do_mmap_elf(loadf, 0L,  ud_mapend,
					ud_prot,
					mapflag,
					ud_mapoff);
			if (BAD_ADDR(u_data)) {
				DBPL("could not map space for task, errno #%d.\n",
					(int)(-(long) u_data));
					retval = u_data;
					goto out;
			}
			ud_size = ud_mapend;
		}
		 DBPL( "# Data segment: %lx\n", u_data);

	 /*
	  * Обнуление данных сегмента после данных, отмапированных из файла.
	  */
		if (ud_allocend > ud_end) {
			unsigned long start_zero = u_data + ud_end;
			unsigned long end_zero = PAGE_ALIGN(u_data + ud_allocend);
			unsigned long start_zeropage = PAGE_ALIGN(start_zero);

			 DBPL( ">>> zero dstart = %#lx, zero dend = %#lx,"
				" dzeropage = %#lx\n", 
				start_zero, end_zero, start_zeropage );
			if (start_zeropage > end_zero) {
				/* Все дополнительные данные находятся
				 * на одной странице сегмента.
				 */
				start_zeropage = end_zero;
			}
										
			 /*
			  * Обнуление заключительной части последней
			 * страницы с данными из файла.
			  */
			if (start_zeropage > start_zero) {
				DBPL( "# Start dzero: %#lx -> %#lx\n", start_zero,
							 start_zeropage);
				clear_user( (void*)start_zero,
						start_zeropage - start_zero );
			}

			 /*
			  * Обнуление остальных страниц.
			 */
			if (end_zero > start_zeropage) {
				DBPL( "# Map dzeropage: %#lx -> %#lx\n",
					 start_zeropage, end_zero);
				ulretval = do_mmap_elf(NULL, start_zeropage,
							end_zero - start_zeropage,
							ud_prot,
							 mapflag | MAP_FIXED,
							0);
				if (BAD_ADDR(ulretval)) {
					DBPL("could not map space for task,"
						" errno #%d.\n",
						(int)(-(long)ulretval));
					retval = ulretval;
					goto out;
				}
				clear_user( (void*)start_zeropage,
						end_zero - start_zeropage);
			}
 		}
		ud_size = PAGE_ALIGN(ud_allocend);
 	} else {
		ud_size = PAGE_ALIGN(ud_end);
	}
 	retval = 0;


	/*
	 * everything is mapped. Do some actions to complete the function
	 */
	if (elf->e_entry) {
		start_point = u_code + elf->e_entry;
		if (start_point >= u_code + uc_end) {
			retval =  -ENOEXEC;
			goto out;
		}
	}
	
	/*
	 * Now search in dynamic section typecount, got offset, got lengh
	*/
	if (dyn) {
                unsigned int i;
		retval = get_dynamic_data(loadf, dyn, &got_off,
                                          &got_sz, &tcount,  &init_got_entry,
                                          &init_entry, &fini_entry, dst_gtt_off,
                                          dst_gtt_sz);
		if (retval) {
			goto out;
		}
		if (check_len(got_sz)) {
			retval =  -ENOEXEC;
			goto out;
		}			
		if (got_off > ud_end - got_sz) {
			retval =  -ENOEXEC;
			goto out;
		}

                for(i = 0; i < 3; i++)
                {
                        if (check_len(dst_gtt_sz[i])) {
                                retval = -ENOEXEC;
                                goto out;
                        }
                        if (dst_gtt_off[i] >= (ud_end - dst_gtt_sz[i])) {
                                retval = -ENOEXEC;
                                goto out;
                        }
                }
	}
	if (mdd) {
                unsigned int i;
		if (init_entry) {
			init_point = init_entry+ u_code;
		}
		if (fini_entry) {
			fini_point = fini_entry + u_code;
		}
		if (init_got_entry) {
			init_got_point = init_got_entry + u_code;
		}
		DBPL("DBPL : populate mdd (0x%lx, 0x%lx, "
			"0x%lx, 0x%lx, 0x%lx, 0x%lx\n",
			u_data + got_off, (u64)got_sz,
			init_got_point,  init_point, fini_point, start_point);
		mdd->got_addr = u_data + got_off;
		mdd->got_len = got_sz;
		mdd->init_got_point = init_got_point;
		mdd->init_point = init_point;
		mdd->fini_point = fini_point;
		mdd->entry_point = start_point;

                /* Заполняем соотвествующие секции модуля (.gott, .gctt и .gompt) тэгированными
                   значениями Object Template, Cast Template и Object Member Pointer. */
                for (i = 0; i < 3; i++) {
                        if (mdd->src_gtt_len[i] != dst_gtt_sz[i]) {
                                DBPL("Wrong size passed for .gtt(#%u): 0x%ux vs 0x%ux\n", i, (unsigned) mdd->src_gtt_len[i], 
                                       (unsigned) dst_gtt_sz[i]); 
                                retval = -ENOEXEC;
                                goto out;
                        }
                        retval = fill_gtt_section(i, (char *) (u_data + dst_gtt_off[i]), mdd->src_gtt_addr[i], dst_gtt_sz[i]);
                        if (retval)
                                goto out;
                }

		retval = create_cut_entry(tcount, u_code, uc_size, u_data, ud_size);
		if (retval) {
			goto out;
		}
	} else {
		DBPL("DBPL : populate current mm\n");
		current->mm->start_code = u_code;
		current->mm->end_code = uc_size;
		current->mm->start_data = u_data;
		current->mm->end_data =  ud_size;
		current->mm->context.tcount = tcount;
	}

	if (entryp) {
		DBPL("DBPL : start_point = 0x%lx\n", start_point);
		*entryp = start_point;
	}
	 return 0;
out:
	{
		struct mm_struct *mm = current->mm;

        	down_write(&mm->mmap_sem);
		if (uc_size) {
        		(void)do_munmap(mm, u_code, uc_size);
		}
		if (ud_size) {
        		(void)do_munmap(mm, u_data, ud_size);
		}		
        	up_write(&mm->mmap_sem);
	}
	return retval;
}



static  int
e2p_load_cu_file(struct file *loadf,
				unsigned long *entryp,
				kmdd_t *mdd)
{
	struct elfhdr		ehdr;
	struct elf_phdr	*elf_phdr = NULL;

	unsigned int		size;
	long			retval = -ENOEXEC;

	
	retval = kernel_read(loadf, 0, (char *)&ehdr, sizeof(ehdr));
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
	retval = kernel_read(loadf, ehdr.e_phoff, (char *)elf_phdr, size);
	if (retval != size) {
		if (retval >= 0) {
			retval = -EIO;
		}
		goto out;
	}

	retval = e2p_load_cu_file_by_headers(loadf, &ehdr,
					elf_phdr, entryp, mdd);
out :
	if (elf_phdr) {
		kfree(elf_phdr);
	}
	return retval;
}


static int load_e2p_load_binary(struct linux_binprm * bprm)
{
	struct pt_regs		*regs = current_pt_regs();
	struct elfhdr		elf_ex;
	struct file		*interpf = NULL; /* to shut gcc up */
	char			*interp_name = NULL;
	struct elf_phdr		*elf_ppnt;
	struct elf_phdr		*elf_phdata;
	int			retval;
	int			i;
	unsigned int		size;
	unsigned long		start_point;
	long			task_flags = 0;

	DBPL("Protected loader elf%d started : %s\n", ELF_CL_SZ, bprm->filename);
	/* Get the exec-header */
	elf_ex = *((struct elfhdr *) bprm->buf);

	retval = e2p_consistensy_check(bprm->file, &elf_ex);
	if (retval != 0) {
		DBPL(" PL-elf%d : file %s rejected\n", ELF_CL_SZ, bprm->filename);
		goto out;
	}

	
	size = elf_ex.e_phnum * sizeof(struct elf_phdr);
	retval = -ENOMEM;
	elf_phdata = (struct elf_phdr *) kmalloc(size, GFP_KERNEL);
	if (!elf_phdata) {
		goto out;
	}
	retval = kernel_read(bprm->file, elf_ex.e_phoff, (char *) elf_phdata, size);
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
		retval = kernel_read(bprm->file, elf_ppnt->p_offset,
				interp_name,  elf_ppnt->p_filesz);
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
	retval = flush_old_exec(bprm);
	if (retval) {
		goto out_free_interp;
	}

	/* OK, This is the point of no return */
	current->mm->start_data = 0;
	current->mm->end_data = 0;
	current->mm->end_code = 0;
	current->mm->mmap = NULL;
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
//	arch_pick_mmap_layout(current->mm);

	retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
				 EXSTACK_DISABLE_X);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_interp_file;
	}

	// load binary or interpreter
	if (interpf) {
		retval = e2p_load_cu_file(interpf, &start_point, NULL);
	} else {
		retval = e2p_load_cu_file_by_headers(bprm->file,
				&elf_ex, elf_phdata, &start_point, NULL);
	}
	if (retval != 0) {
		goto out_free_interp_file;
	}

	set_binfmt(&elf_format);

	// load data for user
	create_elf_tables(bprm);
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




long sys_load_cu(char *name, kmdd_t *mdd)
{
	struct file * file;
	struct path path;
	int error;

        error = user_path(name, &path);
	if (error) {
		goto out;
	}
	error = -EINVAL;
	if (!S_ISREG(path.dentry->d_inode->i_mode)) {
		goto exit;
	}
	error = inode_permission(path.dentry->d_inode, MAY_READ | MAY_EXEC);
	if (error) {
		goto exit;
	}
	file = dentry_open(&path, O_RDONLY, current_cred());
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto exit;
	}
	error = -ENOEXEC;
	if (file->f_op == NULL) {
		fput(file);
		goto exit;
	}

	error = e2p_load_cu_file(file, NULL, mdd);

	fput(file);

out:
  	return error;
exit:
	path_put(&path);
	goto out;
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
MODULE_LICENSE("GPL");







