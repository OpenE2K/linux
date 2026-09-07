/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/binfmts.h>
#include <linux/file.h>
#include "linux/mm.h"
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <linux/elf-randomize.h>
#include "internal.h"

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN	ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN	PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(int)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define STACK_ADD(sp, items) ((elf_addr_t __user *)(sp) - (items))
#define STACK_ROUND(sp, items) \
		(((unsigned long) (sp - items)) & ~15UL)
#define STACK_ALLOC(sp, len) \
({ \
	sp -= len; \
	sp; \
})

#ifdef ELF_COMPAT
#define RTC_ELF_MODE		32
#define X86_TASK_SIZE_EM64T	0xffffe000UL	/* 4G mode */
#define X86_TASK_SIZE		0xc0000000UL	/* 3G mode */
#define X86_ELF_ARCH		EM_386
#else
#define RTC_ELF_MODE		64
#define X86_TASK_SIZE		(0x800000000000ULL - 4096)
#define X86_ELF_ARCH		EM_X86_64
#endif

#define	DEBUG_RTC	0
#define DbgRTC(...)		DebugPrint(DEBUG_RTC, ##__VA_ARGS__)

#define X86_DEFAULT_STACK_SIZE	(2*1024*1024)

static inline unsigned long get_task_size(bool is_support_em64t)
{
#ifdef ELF_COMPAT
	return is_support_em64t ? X86_TASK_SIZE_EM64T : X86_TASK_SIZE;
#else
	return X86_TASK_SIZE;
#endif
}

static inline unsigned long get_x86_elf_et_dyn_base(unsigned long task_size)
{
#ifdef ELF_COMPAT
	return PAGE_ALIGN(task_size / 3) + 0x1000000;
#else
	return task_size / 3 * 2;
#endif
}

/* Secondary space configuration */
struct x86_va_layout {
	unsigned long task_size;
	unsigned long ss_shift;
	unsigned long map_base;
	unsigned long elf_et_dyn_base;
	bool is_topdown;
};

/* arch/x86/include/asm/elf.h */
static inline unsigned long get_task_unmapped_base(unsigned long task_size)
{
	return PAGE_ALIGN(task_size / 3);
}

static inline bool check_x86_arch(struct elfhdr *elf_ex)
{
	return elf_ex->e_machine == X86_ELF_ARCH;
}

static inline bool is_bad_addr(unsigned long addr, unsigned long task_size,
				unsigned long ss_shift)
{
	return addr >= task_size + ss_shift;
}

static inline unsigned long get_ss_shift(void)
{
	e2k_cu_hw0_t cu_hw0;

	if (machine.native_iset_ver < E2K_ISET_V6) {
		return SS_ADDR_START;
	} else {
		cu_hw0 = read_CU_HW0_reg();
		return cu_hw0.upt_sec_ad_shift_dsbl ? 0 : SS_ADDR_START;
	}
}

/*
 * 32-bit bincomp can do mmap above 4G only with MAP_FIXED flag,
 * so pre-calcualte start address for such case.
 */
static unsigned long get_x86_unmapped_area(unsigned long len,
					const struct x86_va_layout *va_layout)
{
	struct vm_unmapped_area_info info;
	unsigned long res;

	info.length		= len;
	info.align_mask		= 0;
	info.align_offset	= 0;

	if (va_layout->is_topdown) {
		info.flags	= VM_UNMAPPED_AREA_TOPDOWN;
		info.low_limit	= va_layout->ss_shift + PAGE_SIZE;
		info.high_limit = va_layout->ss_shift + va_layout->map_base;
	} else {
		info.flags	= 0;
		info.low_limit	= va_layout->ss_shift + va_layout->map_base;
		info.high_limit = va_layout->ss_shift + va_layout->task_size;
	}

	rcu_read_lock();
	res = vm_unmapped_area(&info);
	rcu_read_unlock();

	return res;
}

#ifdef ELF_COMPAT
static struct page *vdsop;
static struct vm_special_mapping vdso_mapping = {
	.name = "[vdso]",
	.pages = &vdsop,
};

static const char vdso_syscall_wraper[] = X86_VDSO_CALL_WRAPPER;
static const char vdso_sigreturn_call[] = X86_VDSO_SIGRETURN_WRAPPER;
static const char vdso_rt_sigreturn_call[] = X86_VDSO_RT_SIGRETURN_WRAPPER;

static int __init init_x86_vdso(void)
{
	vdsop = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!vdsop)
		goto oom;

	memcpy(page_address(vdsop) + X86_VDSO_CALL_OFFSET, vdso_syscall_wraper,
		sizeof(vdso_syscall_wraper));
	memcpy(page_address(vdsop) + X86_VDSO_SIGRETURN_OFFSET, vdso_sigreturn_call,
		sizeof(vdso_sigreturn_call));
	memcpy(page_address(vdsop) + X86_VDSO_RT_SIGRETURN_OFFSET, vdso_rt_sigreturn_call,
		sizeof(vdso_rt_sigreturn_call));

	return 0;

oom:
	pr_err(KERN_ERR "Cannot allocate vdso\n");
	return -ENOMEM;
}

static int install_vdso(struct linux_binprm *bprm,
	struct bincomp_map_info *map_info, const struct x86_va_layout *va_layout)
{
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long vdso_addr;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	vdso_addr = get_x86_unmapped_area(PAGE_SIZE, va_layout);
	DbgRTC("Place vdso at 0x%lx\n", vdso_addr);

	if (is_bad_addr(vdso_addr, va_layout->task_size, va_layout->ss_shift)) {
		mmap_write_unlock(mm);
		return IS_ERR((void *)vdso_addr) ?
			PTR_ERR((void *)vdso_addr) : -EINVAL;
	}

	vma = _install_special_mapping(mm, vdso_addr, PAGE_SIZE,
					VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYEXEC,
					&vdso_mapping);
	mmap_write_unlock(mm);
	if (!IS_ERR(vma))
		map_info->vdso = vdso_addr - va_layout->ss_shift;

	return PTR_ERR_OR_ZERO(vma);
}
#endif

static int
create_elf_tables(struct linux_binprm *bprm, const struct elfhdr *exec,
		unsigned long interp_load_addr, unsigned long e_entry,
		unsigned long phdr_addr, struct bincomp_map_info *map_info)
{
	struct mm_struct *mm = current->mm;
	unsigned long p = bprm->p;
	int argc = bprm->argc;
	int envc = bprm->envc;
	elf_addr_t __user *sp;
	elf_addr_t __user *u_platform;
	elf_addr_t __user *u_base_platform;
	elf_addr_t __user *u_rand_bytes;
	elf_addr_t __user *u_bincomp_data;
	const char *k_platform = ELF_PLATFORM;
	const char *k_base_platform = NULL;
	unsigned char k_rand_bytes[16];
	int items;
	elf_addr_t *elf_info;
	int ei_index;
	const struct cred *cred = current_cred();
	struct vm_area_struct *vma;

	/*
	 * In some cases (e.g. Hyper-Threading), we want to avoid L1
	 * evictions by the processes running on the same package. One
	 * thing we can do is to shuffle the initial stack for them.
	 */

	p = arch_align_stack(p);

	/* Put special structure for bincomp */
	u_bincomp_data = (elf_addr_t __user *)STACK_ALLOC(p, sizeof(*map_info));
	if (copy_to_user(u_bincomp_data, map_info, sizeof(*map_info)))
		return -EFAULT;

	/*
	 * If this architecture has a platform capability string, copy it
	 * to userspace.  In some cases (Sparc), this info is impossible
	 * for userspace to get any other way, in others (i386) it is
	 * merely difficult.
	 */
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}

	/*
	 * If this architecture has a "base" platform capability
	 * string, copy it to userspace.
	 */
	u_base_platform = NULL;
	if (k_base_platform) {
		size_t len = strlen(k_base_platform) + 1;

		u_base_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (copy_to_user(u_base_platform, k_base_platform, len))
			return -EFAULT;
	}

	/*
	 * Generate 16 random bytes for userspace PRNG seeding.
	 */
	get_random_bytes(k_rand_bytes, sizeof(k_rand_bytes));
	u_rand_bytes = (elf_addr_t __user *)
			STACK_ALLOC(p, sizeof(k_rand_bytes));
	if (copy_to_user(u_rand_bytes, k_rand_bytes, sizeof(k_rand_bytes)))
		return -EFAULT;

	/* Create the ELF interpreter info */
	elf_info = (elf_addr_t *)mm->saved_auxv;
	/* update AT_VECTOR_SIZE_BASE if the number of NEW_AUX_ENT() changes */
#define NEW_AUX_ENT(id, val) \
	do { \
		*elf_info++ = id; \
		*elf_info++ = val; \
	} while (0)

#ifdef ARCH_DLINFO
	/*
	 * ARCH_DLINFO must come first so PPC can do its special alignment of
	 * AUXV.
	 * update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT() in
	 * ARCH_DLINFO changes
	 */
	ARCH_DLINFO;
#endif
	NEW_AUX_ENT(AT_HWCAP, ELF_HWCAP);
	NEW_AUX_ENT(AT_PAGESZ, ELF_EXEC_PAGESIZE);
	NEW_AUX_ENT(AT_CLKTCK, CLOCKS_PER_SEC);
	NEW_AUX_ENT(AT_PHDR, phdr_addr);
	NEW_AUX_ENT(AT_PHENT, sizeof(struct elf_phdr));
	NEW_AUX_ENT(AT_PHNUM, exec->e_phnum);
	NEW_AUX_ENT(AT_BASE, interp_load_addr);
	NEW_AUX_ENT(AT_FLAGS, 0);
	NEW_AUX_ENT(AT_ENTRY, e_entry);
	NEW_AUX_ENT(AT_UID, from_kuid_munged(cred->user_ns, cred->uid));
	NEW_AUX_ENT(AT_EUID, from_kuid_munged(cred->user_ns, cred->euid));
	NEW_AUX_ENT(AT_GID, from_kgid_munged(cred->user_ns, cred->gid));
	NEW_AUX_ENT(AT_EGID, from_kgid_munged(cred->user_ns, cred->egid));
	NEW_AUX_ENT(AT_SECURE, bprm->secureexec);
	NEW_AUX_ENT(AT_RANDOM, (elf_addr_t)(unsigned long)u_rand_bytes);
#ifdef ELF_HWCAP2
	NEW_AUX_ENT(AT_HWCAP2, ELF_HWCAP2);
#endif
	NEW_AUX_ENT(AT_EXECFN, bprm->exec);
	if (k_platform) {
		NEW_AUX_ENT(AT_PLATFORM,
			    (elf_addr_t)(unsigned long)u_platform);
	}
	if (k_base_platform) {
		NEW_AUX_ENT(AT_BASE_PLATFORM,
			    (elf_addr_t)(unsigned long)u_base_platform);
	}
	if (bprm->have_execfd) {
		NEW_AUX_ENT(AT_EXECFD, bprm->execfd);
	}
	NEW_AUX_ENT(AT_BINCOMP_INFO, (elf_addr_t)(unsigned long)u_bincomp_data);
#undef NEW_AUX_ENT
	/* AT_NULL is zero; clear the rest too */
	memset(elf_info, 0, (char *)mm->saved_auxv +
			sizeof(mm->saved_auxv) - (char *)elf_info);

	/* And advance past the AT_NULL entry.  */
	elf_info += 2;

	ei_index = elf_info - (elf_addr_t *)mm->saved_auxv;
	sp = STACK_ADD(p, ei_index);

	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);

	/* Point sp at the lowest address on the stack */
	sp = (elf_addr_t __user *)bprm->p;

	/*
	 * Grow the stack manually; some architectures have a limit on how
	 * far ahead a user-space access may be in order to grow the stack.
	 */
	if (mmap_write_lock_killable(mm))
		return -EINTR;
	vma = find_extend_vma_locked(mm, bprm->p);
	mmap_write_unlock(mm);
	if (!vma)
		return -EFAULT;

	/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (put_user(argc, sp++))
		return -EFAULT;

	/* Populate list of argv pointers back to argv strings. */
	p = mm->arg_start;
	mm->arg_end = mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (put_user((elf_addr_t)p, sp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (put_user(0, sp++))
		return -EFAULT;
	mm->arg_end = p;

	/* Populate list of envp pointers back to envp strings. */
	mm->env_end = p;
	mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		if (put_user((elf_addr_t)p, sp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (put_user(0, sp++))
		return -EFAULT;
	mm->env_end = p;

	/* Put the elf_info on the stack in the right place.  */
	if (copy_to_user(sp, mm->saved_auxv, ei_index * sizeof(elf_addr_t)))
		return -EFAULT;
	return 0;
}

static unsigned long elf_map(struct file *filep, unsigned long addr,
			const struct elf_phdr *eppnt, int prot, int flags)
{
	unsigned long map_addr;
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
	unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);

	addr = ELF_PAGESTART(addr);
	size = ELF_PAGEALIGN(size);

	/* mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid */
	if (!size)
		return addr;

	if ((flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) == 0) {
		/* Only fixed mappings are supported */
		return -EINVAL;
	}
	map_addr = vm_mmap(filep, addr, size, prot, flags, off);

	if ((flags & MAP_FIXED_NOREPLACE) && PTR_ERR((void *)map_addr) == -EEXIST)
		DbgRTC("Uhuuh, elf segment at %px requested but the memory is mapped already\n",
			(void *)addr);
	else
		DbgRTC("vma 0x%lx - 0x%lx\n", map_addr, map_addr + size);

	return map_addr;
}

/*
 * In case mmap isn't fixed, the address is chosen automatically, but because
 * of the sec space shift, we may want an allocation over the native TASK_SIZE.
 * This is possible only for fixed mappings, so we need to find free area first.
 */
static unsigned long elf_map_x86(struct file *filep, unsigned long addr,
			const struct elf_phdr *eppnt, int prot, int flags,
			unsigned long total_size,
			const struct x86_va_layout *va_layout)
{
	bool is_fixed = flags & (MAP_FIXED|MAP_FIXED_NOREPLACE);
	unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);

	size = ELF_PAGEALIGN(size);

	if (!is_fixed) {

		if (total_size)
			size = total_size;

		addr = get_x86_unmapped_area(size, va_layout);

		if (is_bad_addr(addr, va_layout->task_size, va_layout->ss_shift))
			return addr;

		flags |= MAP_FIXED;
	}

	return elf_map(filep, addr, eppnt, prot, flags);
}

static unsigned long total_mapping_size(const struct elf_phdr *phdr, int nr)
{
	elf_addr_t min_addr = -1;
	elf_addr_t max_addr = 0;
	bool pt_load = false;
	int i;

	for (i = 0; i < nr; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			min_addr = min(min_addr, ELF_PAGESTART(phdr[i].p_vaddr));
			max_addr = max(max_addr, phdr[i].p_vaddr + phdr[i].p_memsz);
			pt_load = true;
		}
	}
	return pt_load ? (max_addr - min_addr) : 0;
}

static int set_brk(unsigned long start, unsigned long end, int prot)
{
	int error;

	start = ELF_PAGEALIGN(start);
	end = ELF_PAGEALIGN(end);
	if (end > start) {
		/* Map the last of the bss segment. */
		error = vm_brk_flags(start, end - start, 0);
		if (error)
			return error;
	}

	current->mm->start_brk = end;
	current->mm->brk = end;

	return 0;
}

static int set_x86_brk(unsigned long start, unsigned long end,
			int prot, struct bincomp_map_info *info,
			const struct x86_va_layout *va_layout)
{
	int error;

	start	= ELF_PAGEALIGN(start);
	end	= ELF_PAGEALIGN(end);
	if (end > start) {
		/* Map the last of the bss segment into x86 address space. */
		error = vm_mmap(NULL, start, end - start, prot,
				MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0);
		if (is_bad_addr(error, va_layout->task_size, va_layout->ss_shift))
			return -EINVAL;
	}

	info->brk = end - va_layout->ss_shift;

	return 0;
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long elf_bss)
{
	unsigned long nbyte;

	nbyte = ELF_PAGEOFFSET(elf_bss);
	if (nbyte) {
		nbyte = ELF_MIN_ALIGN - nbyte;
		if (clear_user((void __user *) elf_bss, nbyte))
			return -EFAULT;
	}
	return 0;
}

static unsigned long maximum_alignment(struct elf_phdr *cmds, int nr)
{
	unsigned long alignment = 0;
	int i;

	for (i = 0; i < nr; i++) {
		if (cmds[i].p_type == PT_LOAD) {
			unsigned long p_align = cmds[i].p_align;

			/* skip non-power of two alignments as invalid */
			if (!is_power_of_2(p_align))
				continue;
			alignment = max(alignment, p_align);
		}
	}

	/* ensure we align to at least one page */
	return ELF_PAGEALIGN(alignment);
}

static inline int make_prot(u32 p_flags)
{
	int prot = 0;

	if (p_flags & PF_R)
		prot |= PROT_READ;
	if (p_flags & PF_W)
		prot |= PROT_WRITE;
	if (p_flags & PF_X)
		prot |= PROT_EXEC;

	return prot;
}

static int elf_read(struct file *file, void *buf, size_t len, loff_t pos)
{
	ssize_t rv;

	rv = kernel_read(file, buf, len, &pos);
	if (unlikely(rv != len)) {
		return (rv < 0) ? rv : -EIO;
	}
	return 0;
}

/**
 * load_elf_phdrs() - load ELF program headers
 * @elf_ex:   ELF header of the binary whose program headers should be loaded
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF program headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 */
static struct elf_phdr *load_elf_phdrs(const struct elfhdr *elf_ex,
					struct file *elf_file)
{
	struct elf_phdr *elf_phdata = NULL;
	int retval, err = -1;
	unsigned int size;

	/*
	 * If the size of this structure has changed, then punt, since
	 * we will be doing the wrong thing.
	 */
	if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
		goto out;

	/* Sanity check the number of program headers... */
	/* ...and their total size. */
	size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
	if (size == 0 || size > 65536 || size > ELF_MIN_ALIGN)
		goto out;

	elf_phdata = kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	/* Read in the program headers */
	retval = elf_read(elf_file, elf_phdata, size, elf_ex->e_phoff);
	if (retval < 0) {
		err = retval;
		goto out;
	}

	/* Success! */
	err = 0;
out:
	if (err) {
		kfree(elf_phdata);
		elf_phdata = NULL;
	}
	return elf_phdata;
}

/**
 * load_x86_elf_interp() - Loads an x86 elf interpreter
 *
 * @interp_elf_ex:	The interpreter's elfhdr
 * @interpreter:	The interpreter's struct file
 * @interp_elf_phdata:	The interpreter's phdrs
 * @map_info:		Out: X86 data
 * @va_layout:		The secondary space params
 */
static unsigned long load_x86_elf_interp(struct elfhdr *interp_elf_ex,
		struct file *interpreter, struct elf_phdr *interp_elf_phdata,
		struct bincomp_map_info *map_info,
		const struct x86_va_layout *va_layout)
{
	struct elf_phdr *eppnt;
	unsigned long load_addr = 0;
	int load_addr_set = 0;
	unsigned long last_bss = 0, elf_bss = 0;
	int bss_prot = 0;
	unsigned long error = ~0UL;
	unsigned long total_size;
	unsigned long task_size = va_layout->task_size;
	unsigned long ss_shift	= va_layout->ss_shift;
	int i;

	DbgRTC("load_x86_elf_interp\n");

	/* First of all, some simple consistency checks */
	if (interp_elf_ex->e_type != ET_EXEC &&
	    interp_elf_ex->e_type != ET_DYN)
		goto out;
	if (!check_x86_arch(interp_elf_ex))
		goto out;
	if (!interpreter->f_op->mmap)
		goto out;

	total_size = total_mapping_size(interp_elf_phdata,
					interp_elf_ex->e_phnum);
	if (!total_size) {
		error = -EINVAL;
		goto out;
	}

	eppnt = interp_elf_phdata;
	for (i = 0; i < interp_elf_ex->e_phnum; i++, eppnt++) {
		if (eppnt->p_type == PT_LOAD) {
			int elf_flags = MAP_PRIVATE;
			int elf_prot = make_prot(eppnt->p_flags);
			unsigned long vaddr = 0;
			unsigned long k, map_addr;

			vaddr = eppnt->p_vaddr;
			if (interp_elf_ex->e_type == ET_EXEC || load_addr_set)
				elf_flags |= MAP_FIXED;

			map_addr = elf_map_x86(interpreter, load_addr + vaddr,
					eppnt, elf_prot, elf_flags, total_size,
					va_layout);
			total_size = 0;
			error = map_addr;
			if (is_bad_addr(map_addr, task_size, ss_shift))
				goto out;

			if (!load_addr_set && interp_elf_ex->e_type == ET_DYN) {
				load_addr = map_addr - ELF_PAGESTART(vaddr);
				load_addr_set = 1;
			}

			/*
			 * Check to see if the section's size will overflow the
			 * allowed task size. Note that p_filesz must always be
			 * <= p_memsize so it's only necessary to check p_memsz.
			 */
			k = load_addr + eppnt->p_vaddr;
			if (is_bad_addr(k, task_size, ss_shift) ||
			    eppnt->p_filesz > eppnt->p_memsz ||
			    eppnt->p_memsz > task_size ||
			    task_size - eppnt->p_memsz < k - ss_shift) {
				error = -ENOMEM;
				goto out;
			}

			/*
			 * Find the end of the file mapping for this phdr, and
			 * keep track of the largest address we see for this.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_filesz;
			if (k > elf_bss)
				elf_bss = k;

			/*
			 * Do the same thing for the memory mapping - between
			 * elf_bss and last_bss is the bss section.
			 */
			k = load_addr + eppnt->p_vaddr + eppnt->p_memsz;
			if (k > last_bss) {
				last_bss = k;
				bss_prot = elf_prot;
			}
		}
	}

	/*
	 * Now fill out the bss section: first pad the last page from
	 * the file up to the page boundary, and zero it from elf_bss
	 * up to the end of the page.
	 */
	if (padzero(elf_bss)) {
		error = -EFAULT;
		goto out;
	}
	/*
	 * Next, align both the file and mem bss up to the page size,
	 * since this is where elf_bss was just zeroed up to, and where
	 * last_bss will end after the vm_brk_flags() below.
	 */
	elf_bss = ELF_PAGEALIGN(elf_bss);
	last_bss = ELF_PAGEALIGN(last_bss);
	/* Finally, if there is still more bss to allocate, do it. */
	if (last_bss > elf_bss) {
		error = set_x86_brk(elf_bss, last_bss - elf_bss, bss_prot,
				    map_info, va_layout);
		if (error)
			goto out;
	}

	error = load_addr;
out:
	return error;
}

/**
 * Map stack for x86 executable
 */
static int map_x86_stack(struct linux_binprm *bprm, int executable_stack,
			struct bincomp_map_info *info,
			const struct x86_va_layout *va_layout)
{
	unsigned long stack_size, rlimit, stack_top, stack;
	int flags, prot;

	rlimit = current->signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_cur;
	rlimit = rlimit & PAGE_MASK;
	stack_size = X86_DEFAULT_STACK_SIZE;
	if (stack_size > rlimit)
		return -EFAULT;

	stack_top = va_layout->task_size + va_layout->ss_shift;
	flags = MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS;
	prot = PROT_READ|PROT_WRITE;

	if (executable_stack != EXSTACK_DISABLE_X)
		prot |= PROT_EXEC;

	stack = round_down(stack_top - stack_size, PAGE_SIZE);
	stack = vm_mmap(NULL, stack, stack_size, prot, flags, 0);
	if ((is_bad_addr(stack, va_layout->task_size, va_layout->ss_shift)))
		return IS_ERR((void *)stack)
			? PTR_ERR((void *)stack)
			: -EINVAL;

	info->rsp = stack + stack_size - va_layout->ss_shift;

	return 0;
}

/**
 * read_x86_elf_interp() - open the interpreter and read elf
 * @file:		The x86 executable struct file
 * @elf_ex:		The x86 executable elfhdr buf
 * @elf_ppnt:		The x86 executable elf phdrs
 * @interp_file_p:	Out: The interpreter's elf struct file
 * @interp_elf_ex_p:	Out: The interpreter's elfhdr buf
 * @executable_stack_p:	Out: Stack params
 */
static int read_x86_elf_interp(struct file *file, struct elfhdr *elf_ex,
		struct elf_phdr *elf_ppnt, struct file **interp_file_p,
		struct elfhdr **interp_elf_ex_p, int *executable_stack_p)
{
	char *path = NULL;
	struct file *interp_file = NULL;
	struct elfhdr *interp_elf_ex = NULL;
	bool interp_found = false;
	int i, res = 0;

	for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++) {
		if (!interp_found && (elf_ppnt->p_type == PT_INTERP)) {
			res = -ENOEXEC;
			if (elf_ppnt->p_filesz > PATH_MAX
				|| elf_ppnt->p_filesz < 2)
				goto out;

			res = -ENOMEM;
			path = kmalloc(elf_ppnt->p_filesz, GFP_KERNEL);
			if (!path)
				goto out;

			res = elf_read(file, path, elf_ppnt->p_filesz,
					elf_ppnt->p_offset);
			if (res < 0)
				goto out_free_path;

			/* make sure path is NULL terminated */
			res = -ENOEXEC;
			if (path[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_path;

			interp_file = open_exec(path);
			res = PTR_ERR(interp_file);
			if (IS_ERR(interp_file))
				goto out_free_path;

			res = -ENOMEM;
			interp_elf_ex = kmalloc(sizeof(*interp_elf_ex),
						GFP_KERNEL);
			if (!interp_elf_ex)
				goto out_put_file;

			res = elf_read(interp_file, interp_elf_ex,
					sizeof(*interp_elf_ex), 0);
			if (res < 0)
				goto out_put_file_free;

			interp_found = true;

		} else if (elf_ppnt->p_type == PT_GNU_STACK) {
			*executable_stack_p = (elf_ppnt->p_flags & PF_X)
						? EXSTACK_ENABLE_X
						: EXSTACK_DISABLE_X;
		}
	}

	*interp_file_p		= interp_file;
	*interp_elf_ex_p	= interp_elf_ex;

out_free_path:
	kfree(path);
out:
	return res;

out_put_file_free:
	kfree(interp_elf_ex);

out_put_file:
	allow_write_access(interp_file);
	fput(interp_file);
	goto out_free_path;
}

/**
 * check_bincomp_interp() - Check that the bincomp elf doesn't have PT_INTERP
 * @file:	The x86 executable struct file
 * @elf_ex:	The x86 executable elfhdr buf
 * @elf_ppnt:	The x86 executable elf phdrs
 */
static int check_bincomp_interp(struct file *file, struct elfhdr *elf_ex,
				struct elf_phdr *elf_ppnt)
{
	int i, res = 0;

	for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++) {
		if (elf_ppnt->p_type == PT_INTERP) {
			res = -ENOEXEC;
			pr_warn("rtc_binfmt: dynamic-linked binary compiler is not supported\n");
			goto out;
		}
	}

out:
	return res;
}


#define RTC_FUNC_MODE(name, mode, args...) rtc_##name##mode(args)
#define RTC_ELF_FUNC(name, mode, args...) RTC_FUNC_MODE(name, mode, args)

static void init_x86_va_layout(bool is_support_em64t, bool is_topdown,
				struct x86_va_layout *va_layout)
{
	unsigned long task_size = get_task_size(is_support_em64t);

	va_layout->task_size	= task_size;
	va_layout->ss_shift	= get_ss_shift();
	va_layout->is_topdown	= is_topdown;
	va_layout->elf_et_dyn_base = get_x86_elf_et_dyn_base(task_size);

	/* arch/x86/mm/mmap.c: mmap_base() */
	if (is_topdown) {
		unsigned long gap = current->signal->bin_comp_rlim[BC_RLIMIT_X86_STACK].rlim_cur;
		unsigned long pad = stack_guard_gap;
		unsigned long gap_min, gap_max;

		/* Values close to RLIM_INFINITY can overflow. */
		if (gap + pad > gap)
			gap += pad;

		/*
		 * Top of mmap area (just below the process stack).
		 * Leave an at least ~128 MB hole.
		 */
		gap_min = (128 * 1024 * 1024UL);
		gap_max = (task_size / 6) * 5;

		if (gap < gap_min)
			gap = gap_min;
		else if (gap > gap_max)
			gap = gap_max;

		va_layout->map_base = PAGE_ALIGN(task_size - gap);
	} else
		va_layout->map_base = get_task_unmapped_base(task_size);
}

/**
 * rtc_load_x86_elf() - Load an x86 elf
 *
 * @bprm:		The arguments for loading binary
 * @map_info:		Out: The loaded binary's data
 * @is_support_em64t:	The bincomp supports 4G layout
 * @is_topdown:		X86 address space layout
 */
int RTC_ELF_FUNC(load_x86_elf, RTC_ELF_MODE, struct linux_binprm *bprm,
			struct bincomp_map_info *map_info,
			bool is_support_em64t, bool is_topdown)
{
	struct file *interpreter = NULL;
	unsigned long load_addr, load_bias, phdr_addr = 0;
	int load_addr_set = 0;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
	unsigned long elf_bss, elf_brk;
	int bss_prot = 0;
	int retval, i;
	unsigned long elf_entry;
	unsigned long e_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	int executable_stack = EXSTACK_DEFAULT;
	struct elfhdr *elf_ex = (struct elfhdr *)bprm->buf;
	struct elfhdr *interp_elf_ex = NULL;
	struct x86_va_layout va_layout;
	unsigned long ss_shift;
	unsigned long task_size;
	unsigned long map_base;

	DbgRTC("map x86 elf\n");

	if (!check_x86_arch(elf_ex))
		return -EINVAL;

	init_x86_va_layout(is_support_em64t, is_topdown, &va_layout);

	ss_shift	= va_layout.ss_shift;
	task_size	= va_layout.task_size;
	map_base	= va_layout.map_base;

	load_bias = ss_shift;

	DbgRTC("task_size = 0x%lx, map_base = 0x%lx, ss_shift = 0x%lx\n",
			task_size, map_base, ss_shift);
	DbgRTC("is_support_em64t = %d is_topdown = %d elf_et_dyn_base = 0x%lx\n",
			is_support_em64t, is_topdown, va_layout.elf_et_dyn_base);

	retval = -ENOEXEC;

	elf_phdata = load_elf_phdrs(elf_ex, bprm->file);
	if (!elf_phdata)
		goto out;

	retval = read_x86_elf_interp(bprm->file, elf_ex, elf_phdata,
			&interpreter, &interp_elf_ex, &executable_stack);
	if (retval)
		goto out_free_ph;

	/* Some simple consistency checks for the interpreter */
	if (interpreter) {
		retval = -ELIBBAD;
		/* Not an ELF interpreter */
		if (memcmp(interp_elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
			goto out_free_dentry;
		/* Verify the interpreter has a valid arch */
		if (!check_x86_arch(interp_elf_ex))
			goto out_free_dentry;

		/* Load the interpreter program headers */
		interp_elf_phdata = load_elf_phdrs(interp_elf_ex,
						   interpreter);
		if (!interp_elf_phdata)
			goto out_free_dentry;
	}

	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	/* mmap x86 stack first */
	retval = map_x86_stack(bprm, executable_stack, map_info, &va_layout);
	DbgRTC("map_x86_stack = %d, 0x%llx\n", retval, map_info->rsp + ss_shift);

	if ((is_bad_addr(retval, task_size, ss_shift)))
		goto out_free_dentry;


	/* Now we do a little grungy work by mmapping the ELF image into
	   the correct location in memory. */
	for (i = 0, elf_ppnt = elf_phdata;
		i < elf_ex->e_phnum; i++,
		elf_ppnt++) {

		int elf_prot, elf_flags;
		unsigned long k, vaddr;
		unsigned long total_size = 0;
		unsigned long alignment;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely(elf_brk > elf_bss)) {
			unsigned long nbyte;

			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			retval = set_x86_brk(elf_bss + load_bias,
						elf_brk + load_bias,
						bss_prot, map_info,
						&va_layout);

			if (retval)
				goto out_free_dentry;
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		elf_prot = make_prot(elf_ppnt->p_flags);

		elf_flags = MAP_PRIVATE;

		vaddr = elf_ppnt->p_vaddr;
		/*
		 * If we are loading ET_EXEC or we have already performed
		 * the ET_DYN load_addr calculations, proceed normally.
		 */
		if (elf_ex->e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (elf_ex->e_type == ET_DYN) {
			/*
			 * This logic is run once for the first LOAD Program
			 * Header for ET_DYN binaries to calculate the
			 * randomization (load_bias) for all the LOAD
			 * Program Headers, and to calculate the entire
			 * size of the ELF mapping (total_size). (Note that
			 * load_addr_set is set to true later once the
			 * initial mapping is performed.)
			 *
			 * There are effectively two types of ET_DYN
			 * binaries: programs (i.e. PIE: ET_DYN with INTERP)
			 * and loaders (ET_DYN without INTERP, since they
			 * _are_ the ELF interpreter). The loaders must
			 * be loaded away from programs since the program
			 * may otherwise collide with the loader (especially
			 * for ET_EXEC which does not have a randomized
			 * position). For example to handle invocations of
			 * "./ld.so someprog" to test out a new version of
			 * the loader, the subsequent program that the
			 * loader loads must avoid the loader itself, so
			 * they cannot share the same load range. Sufficient
			 * room for the brk must be allocated with the
			 * loader as well, since brk must be available with
			 * the loader.
			 *
			 * Therefore, programs are loaded offset from
			 * ELF_ET_DYN_BASE and loaders are loaded into the
			 * independently randomized mmap region (0 load_bias
			 * without MAP_FIXED).
			 */
			if (interpreter) {
				load_bias = ss_shift + va_layout.elf_et_dyn_base;

				alignment = maximum_alignment(elf_phdata,
					elf_ex->e_phnum);
				if (alignment)
					load_bias &= ~(alignment - 1);
				elf_flags |= MAP_FIXED_NOREPLACE;
			}

			/*
			 * Since load_bias is used for all subsequent loading
			 * calculations, we must lower it by the first vaddr
			 * so that the remaining calculations based on the
			 * ELF vaddrs will be correctly offset. The result
			 * is then page aligned.
			 */
			load_bias = ELF_PAGESTART(load_bias - vaddr);

			total_size = total_mapping_size(elf_phdata,
							elf_ex->e_phnum);
			if (!total_size) {
				retval = -EINVAL;
				goto out_free_dentry;
			}
		}

		error = elf_map_x86(bprm->file, load_bias + vaddr, elf_ppnt,
					elf_prot, elf_flags, total_size,
					&va_layout);
		total_size = 0;

		if (is_bad_addr(error, task_size, ss_shift)) {
			retval = IS_ERR((void *)error) ? PTR_ERR((void *)error) : -EINVAL;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (elf_ex->e_type == ET_DYN) {
				load_bias += error -
					      ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
			}
		}

		/*
		 * Figure out which segment in the file contains the Program
		 * Header table, and map to the associated memory address.
		 */
		if (elf_ppnt->p_offset <= elf_ex->e_phoff &&
		    elf_ex->e_phoff < elf_ppnt->p_offset + elf_ppnt->p_filesz) {
			phdr_addr = elf_ex->e_phoff - elf_ppnt->p_offset +
				    elf_ppnt->p_vaddr;
		}

		k = elf_ppnt->p_vaddr;
		if ((elf_ppnt->p_flags & PF_X) && k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (is_bad_addr(k, task_size, ss_shift) ||
		    elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > task_size ||
		    task_size - elf_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			retval = -EINVAL;
			goto out_free_dentry;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk) {
			bss_prot = elf_prot;
			elf_brk = k;
		}
	}

	e_entry = elf_ex->e_entry + load_bias;
	phdr_addr += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
	retval = set_x86_brk(elf_bss, elf_brk, bss_prot,
			     map_info, &va_layout);
	if (retval)
		goto out_free_dentry;

	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_dentry;
	}

	if (interpreter) {
		/* interpreter is allowed only for x86. */
		elf_entry = load_x86_elf_interp(interp_elf_ex, interpreter,
						interp_elf_phdata, map_info,
						&va_layout);
		if (!IS_ERR((void *)elf_entry)) {
			/*
			 * load_x86_elf_interp() returns relocation
			 * adjustment
			 */
			interp_load_addr = elf_entry;
			elf_entry += interp_elf_ex->e_entry;
		}
		if (is_bad_addr(elf_entry, task_size, ss_shift)) {
			retval = IS_ERR((void *)elf_entry) ?
					(int)elf_entry : -EINVAL;
			goto out_free_dentry;
		}

		allow_write_access(interpreter);
		fput(interpreter);

		kfree(interp_elf_ex);
		kfree(interp_elf_phdata);
	} else {
		elf_entry = e_entry;
		if (is_bad_addr(elf_entry, task_size, ss_shift)) {
			retval = -EINVAL;
			goto out_free_dentry;
		}
	}
	kfree(elf_phdata);

#ifdef ELF_COMPAT
	retval = install_vdso(bprm, map_info, &va_layout);
	if (retval < 0)
		goto out;
#endif
	map_info->rip		= elf_entry - ss_shift;
	map_info->at_base	= interp_load_addr - ss_shift;
	map_info->at_entry	= e_entry - ss_shift;
	map_info->at_phnum	= elf_ex->e_phnum;
	map_info->at_phent	= sizeof(struct elf_phdr);
	map_info->at_phdr	= phdr_addr - ss_shift;

	retval = 0;

out:
	return retval;

out_free_dentry:
	kfree(interp_elf_ex);
	kfree(interp_elf_phdata);

	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);

out_free_ph:
	kfree(elf_phdata);
	goto out;
}

/**
 * rtc_load_bincomp_elf() - Load the binary compiler
 *
 * @bprm:	The arguments for loading binary
 * @map_info:	The arguments to put on the binary compiler's stack
 */
int RTC_ELF_FUNC(load_bincomp_elf, RTC_ELF_MODE, struct linux_binprm *bprm,
			struct bincomp_map_info *map_info)
{
	unsigned long load_addr, load_bias = 0, phdr_addr = 0;
	int load_addr_set = 0;
	unsigned long error;
	struct elf_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int bss_prot = 0;
	int retval, i;
	unsigned long elf_entry;
	unsigned long e_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	struct elfhdr *elf_ex = (struct elfhdr *)bprm->buf;
	struct mm_struct *mm;
	struct pt_regs *regs;

	DbgRTC("map bincomp\n");

	retval = -ENOEXEC;
	if (!elf_check_arch(elf_ex))
		goto out;

	elf_phdata = load_elf_phdrs(elf_ex, bprm->file);
	if (!elf_phdata)
		goto out;

	/* Check that bincomp elf doesn't have interpreter */
	retval = check_bincomp_interp(bprm->file, elf_ex, elf_phdata);
	if (retval)
		goto out_free_ph;

	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	/**
	 * Now we do a little grungy work by mmapping the ELF image into
	 * the correct location in memory.
	 */
	for (i = 0, elf_ppnt = elf_phdata; i < elf_ex->e_phnum; i++, elf_ppnt++) {
		int elf_prot, elf_flags;
		unsigned long k, vaddr;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely(elf_brk > elf_bss)) {
			unsigned long nbyte;

			/*
			 * There was a PT_LOAD segment with p_memsz > p_filesz
			 * before this one. Map anonymous pages, if needed,
			 * and clear the area.
			 */
			retval = set_brk(elf_bss + load_bias,
					elf_brk + load_bias,
					bss_prot);

			if (retval)
				goto out_free_ph;
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void __user *)elf_bss +
							load_bias, nbyte)) {
					/*
					 * This bss-zeroing can fail if the ELF
					 * file specifies odd protections. So
					 * we don't check the return value
					 */
				}
			}
		}

		elf_prot = make_prot(elf_ppnt->p_flags);

		elf_flags = MAP_PRIVATE;

		vaddr = elf_ppnt->p_vaddr;
		/*
		 * If we are loading ET_EXEC or we have already performed
		 * the ET_DYN load_addr calculations, proceed normally.
		 */
		if (elf_ex->e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (elf_ex->e_type == ET_DYN) {
			retval = -ENOEXEC;
			pr_warn("rtc_binfmt: ET_DYN found\n");
			goto out_free_ph;
		}

		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags);

		if (is_bad_addr(error, TASK_SIZE, 0)) {
			retval = IS_ERR((void *)error)
					? PTR_ERR((void *)error)
					: -EINVAL;
			goto out_free_ph;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (elf_ex->e_type == ET_DYN) {
				load_bias += error -
					      ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
			}
		}

		/*
		 * Figure out which segment in the file contains the Program
		 * Header table, and map to the associated memory address.
		 */
		if (elf_ppnt->p_offset <= elf_ex->e_phoff &&
		    elf_ex->e_phoff < elf_ppnt->p_offset + elf_ppnt->p_filesz) {
			phdr_addr = elf_ex->e_phoff - elf_ppnt->p_offset +
				    elf_ppnt->p_vaddr;
		}

		k = elf_ppnt->p_vaddr;
		if ((elf_ppnt->p_flags & PF_X) && k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (is_bad_addr(k, TASK_SIZE, 0) ||
		    elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
		    elf_ppnt->p_memsz > TASK_SIZE ||
		    TASK_SIZE - elf_ppnt->p_memsz < k) {
			/* set_brk can never work. Avoid overflows. */
			retval = -EINVAL;
			goto out_free_ph;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk) {
			bss_prot = elf_prot;
			elf_brk = k;
		}
	}

	e_entry = elf_ex->e_entry + load_bias;
	phdr_addr += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections.  We must do this before
	 * mapping in the interpreter, to make sure it doesn't wind
	 * up getting placed where the bss needs to go.
	 */
	retval = set_brk(elf_bss, elf_brk, bss_prot);

	if (retval)
		goto out_free_ph;
	if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
		retval = -EFAULT; /* Nobody gets to see this, but.. */
		goto out_free_ph;
	}

	elf_entry = e_entry;
	if (is_bad_addr(elf_entry, TASK_SIZE, 0)) {
		retval = -EINVAL;
		goto out_free_ph;
	}

	kfree(elf_phdata);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = ARCH_SETUP_ADDITIONAL_PAGES(bprm, elf_ex, false);
	if (retval < 0)
		goto out;
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	retval = create_elf_tables(bprm, elf_ex, interp_load_addr,
				   e_entry, phdr_addr, map_info);
	if (retval < 0)
		goto out;

	mm = current->mm;
	mm->end_code = end_code;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;

	if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
		mm->brk = arch_randomize_brk(mm);
		mm->start_brk = mm->brk;
#ifdef compat_brk_randomized
		current->brk_randomized = 1;
#endif
	}
	regs = current_pt_regs();

	finalize_exec(bprm);
	START_THREAD(elf_ex, regs, elf_entry, bprm->p);

	retval = 0;

out:
	return retval;

out_free_ph:
	kfree(elf_phdata);
	goto out;
}


#ifdef ELF_COMPAT
late_initcall(init_x86_vdso);
#endif
