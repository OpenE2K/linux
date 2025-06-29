/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/personality.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include "internal.h"

static char *startx86_path;
static DEFINE_RWLOCK(spath_lock);

/* configuring exe file for rtc_proc filesystem */
static void rtcfs_set_exe_file(bin_comp_info_t *bi, struct file *x86_exe)
{
	write_lock(&bi->lock);
	if (bi->exe_file) {
		/* releasing old file */
		allow_write_access(bi->exe_file);
		fput(bi->exe_file);
	}
	bi->exe_file = x86_exe;
	write_unlock(&bi->lock);
}

static bool is_elf_compat(const char *buf)
{
	struct elfhdr *elf_ex = (struct elfhdr *)buf;

	return elf_ex->e_ident[EI_CLASS] != ELFCLASS64;
}

static int add_bincomp_args(struct linux_binprm *bprm, void *info,
				size_t size, u64 args_offsets_offset)
{
	u64 argv_off, *argv_off_p;
	char *argv_end, *arg;
	int ret, i;
	size_t len;

	ret = -EFAULT;
	if (!args_offsets_offset
			|| args_offsets_offset > size - 1
			|| memcmp(info + size - 1, "\0", 1))
		goto out;

	if (check_add_overflow((u64)info, args_offsets_offset, &argv_off)
			|| argv_off != (uintptr_t)argv_off)
		goto out;

	argv_off_p = (u64 *)argv_off;

	for (i = 0; argv_off_p[i]; i++)
		if (argv_off_p[i] > size - 1)
			goto out;

	/* address of last (NULL) argv_off element*/
	argv_end = (char *)&argv_off_p[i];

	/* delimiter goes first */
	ret = copy_string_kernel("--", bprm);
	if (ret < 0)
		goto out;
	bprm->argc++;

	if (i < 1) {
		ret = 0; /* nothing to add*/
		goto out;
	}

	/* processing in reverse order */
	for (i -= 1; i >= 0; i--) {
		arg = (char *)info + argv_off_p[i];
		if (arg <= argv_end) {
			ret = -EFAULT;
			goto out;
		}

		len = strnlen(arg, MAX_ARG_STRLEN) + 1;
		if (len > MAX_ARG_STRLEN) {
			ret = -E2BIG;
			goto out;
		}

		ret = copy_string_kernel(arg, bprm);
		if (ret < 0)
			goto out;
		bprm->argc++;
	}
out:
	return ret;
}

static int exec_helper(struct linux_binprm *bprm)
{
	struct file *startx86, *x86_exe;
	int ret;

	ret = copy_string_kernel("--", bprm);
	if (ret)
		goto out;
	bprm->argc++;

	ret = copy_string_kernel(bprm->interp, bprm);
	if (ret)
		goto out;
	bprm->argc++;

	read_lock(&spath_lock);
	if (startx86_path && startx86_path[0] == '/')
		ret = bprm_change_interp(startx86_path, bprm);
	read_unlock(&spath_lock);

	if (ret)
		goto out;

	startx86 = filp_open(bprm->interp, O_LARGEFILE | O_RDONLY | __FMODE_EXEC, 0);
	if (IS_ERR(startx86)) {
		ret = PTR_ERR(startx86);
		pr_warn("Unable to open executable file '%s', err %d\n",
					startx86_path, ret);
		goto out;
	}

	ret = deny_write_access(startx86);
	if (ret) {
		fput(startx86);
		goto out;
	}

	bprm->interpreter = startx86;
	x86_exe = bprm->file;

	would_dump(bprm, x86_exe);

out:
	return ret;
}

enum bincomp_exec_type {
	EXEC_TYPE_FD = 0u,
	EXEC_TYPE_MMAP,
	EXEC_TYPE_UNKNOWN
};

static int load_rtc(struct linux_binprm *bprm);

static struct linux_binfmt rtc_elf_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_rtc,
};

static int exec_rtc(bin_comp_info_t *bi, struct linux_binprm *bprm)
{
	struct file *bincomp_file;
	bool e2k_compat, x86_compat;
	char x86_elf_ex[BINPRM_BUF_SIZE];
	char e2k_elf_ex[BINPRM_BUF_SIZE];
	struct elfhdr *elf_ex;
	struct file *x86_file;
	struct bincomp_map_info map_info;
	union bincomp_info_header *hdr;
	u64 exec_type = EXEC_TYPE_FD;
	loff_t pos = 0;
	void *bi_info;
	size_t bi_info_size;
	int ret;

	x86_compat = is_elf_compat(bprm->buf);

	read_lock(&bi->lock);

	/* binary compiler should be already opened */
	bincomp_file = x86_compat ? bi->rtc32 : bi->rtc64;

	if (!bincomp_file) {
		ret = -ENOENT;
		goto out_unlock;
	}

	if (!bi->info || !bi->info_size) {
		ret = -EINVAL;
		goto out_unlock;
	}

	bi_info_size = bi->info_size;
	bi_info = kmalloc(bi_info_size, GFP_ATOMIC);
	if (!bi_info) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	memcpy(bi_info, bi->info, bi_info_size);

	read_unlock(&bi->lock);

	hdr = (union bincomp_info_header *)bi_info;
	if (hdr->v0.version >= 1)
		exec_type = hdr->v1.exec_type;

	if (exec_type >= EXEC_TYPE_UNKNOWN) {
		ret = -EINVAL;
		kfree(bi_info);
		goto out;
	}

	ret = add_bincomp_args(bprm, bi_info, bi_info_size,
				hdr->v0.args_offsets_offset);
	kfree(bi_info);
	if (ret)
		goto out;

	x86_file = bprm->file;

	ret = deny_write_access(bincomp_file);
	if (ret)
		goto out;

	get_file(bincomp_file);
	would_dump(bprm, x86_file);

	if (exec_type == EXEC_TYPE_FD) {
		/* mark the bprm that fd should be passed to interp */
		bprm->interpreter = bincomp_file;
		bprm->have_execfd = 1;
		bprm->execfd_creds = 1;

		/*
		 * Get additional refcnt and call deny_write_access one more
		 * time because exec_binprm will put them for x86 exutable
		 * (bprm->file) later. Counter and write access will be fixed
		 * upon task exit in free_bin_comp_info().
		 */
		ret = deny_write_access(x86_file);
		if (ret) {
			allow_write_access(bincomp_file);
			fput(bincomp_file);
			goto out;
		}

		get_file(x86_file);

		/* store ref to file (rtc_proc's) /proc/<pid>/exe symlink points to */
		rtcfs_set_exe_file(bi, x86_file);
	} else {
		memcpy(x86_elf_ex, bprm->buf, BINPRM_BUF_SIZE);

		/* prepare exec with real executable */
		bprm->file = bincomp_file;

		/*
		 * Don't need to manipulate with x86_file refcntrs because it's
		 * come from bprm->file with proper values and nothing will be
		 * passed back through bprm->interpreter (no references will
		 * be dropped). On error, free_bprm() will fix refcntr and
		 * write access for bprm->file, and free_bincomp_info() will
		 * take care of x86_file.
		 */
		rtcfs_set_exe_file(bi, x86_file);

		memset(bprm->buf, 0, BINPRM_BUF_SIZE);

		ret = kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
		if (ret < 0)
			goto out;

		memcpy(e2k_elf_ex, bprm->buf, BINPRM_BUF_SIZE);

		/* check bincomp elf */
		ret = -EACCES;
		elf_ex = (struct elfhdr *)e2k_elf_ex;
		if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
			goto out;
		if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
			goto out;
		if (!bprm->file->f_op->mmap)
			goto out;

		e2k_compat = is_elf_compat(bprm->buf);

		/* crutch for setting up right creds (see bprm_creds_from_file()) */
		bprm->executable = x86_file;
		bprm->execfd_creds = 1;

		ret = begin_new_exec(bprm);

		bprm->executable = NULL;
		bprm->execfd_creds = 0;

		if (ret)
			goto out;

		if (e2k_compat)	{
			struct elf32_hdr *hdr = (struct elf32_hdr *)bprm->buf;

			SET_PERSONALITY2(*hdr, NULL);
		} else {
			struct elf64_hdr *hdr = (struct elf64_hdr *)bprm->buf;

			SET_PERSONALITY2(*hdr, NULL);
		}

		if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
			current->flags |= PF_RANDOMIZE;

		setup_new_exec(bprm);

		ret = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
					 EXSTACK_DEFAULT);
		if (ret < 0)
			goto out;

		set_binfmt(&rtc_elf_format);

		bprm->file = x86_file;
		memcpy(bprm->buf, x86_elf_ex, BINPRM_BUF_SIZE);

		/* map x86 binary */
		if (x86_compat)
			ret = rtc_load_elf32(bprm, &map_info);
		else
			ret = rtc_load_elf64(bprm, &map_info);

		if (ret) {
			/* Force free_bprm() to fix bincomp_file */
			bprm->file = bincomp_file;
			goto out;
		}

		bprm->file = bincomp_file;
		memcpy(bprm->buf, e2k_elf_ex, BINPRM_BUF_SIZE);

		/* map real executable and start a new process */
		if (e2k_compat)
			ret = rtc_load_elf32(bprm, &map_info);
		else
			ret = rtc_load_elf64(bprm, &map_info);
	}

out:
	return ret;

out_unlock:
	read_unlock(&bi->lock);
	return ret;
}

/* Preparing bprm before binfmt_elf processes this execve */
static int load_rtc(struct linux_binprm *bprm)
{
	bin_comp_info_t *bi;
	struct elfhdr *elf_ex;

	elf_ex = (struct elfhdr *)bprm->buf;

	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0 ||
			elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN ||
			elf_ex->e_machine != EM_X86_64 && elf_ex->e_machine != EM_386 ||
			!bprm->file->f_op->mmap)
		return -ENOEXEC;

	if (WARN_ON_ONCE(!S_ISREG(file_inode(bprm->file)->i_mode) ||
			 path_noexec(&bprm->file->f_path)))
		return -EACCES;

	bi = &bprm->mm->context.bincomp_info;

	if (bi->startx86_pid_ns == NULL)
		/* first run: execute startx86 helper */
		return exec_helper(bprm);

	return exec_rtc(bi, bprm);
}

static int proc_spath_show(struct seq_file *m, void *v)
{
	read_lock(&spath_lock);
	seq_printf(m, "%s\n", startx86_path);
	read_unlock(&spath_lock);

	return 0;
}

static ssize_t proc_spath_write(struct file *filp, const char __user *ubuf,
				size_t count, loff_t *off)
{
	char buf[PATH_MAX];

	if (count >= PATH_MAX)
		return -ENAMETOOLONG;

	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	if (buf[0] == '\n' && count == 1) {
		write_lock(&spath_lock);
		kfree(startx86_path);
		startx86_path = NULL;
		write_unlock(&spath_lock);
		return count;
	}

	if (buf[0] != '/')
		return -EINVAL;

	if (buf[count - 1] == '\n')
		buf[count - 1] = 0;
	else
		buf[count] = 0;

	write_lock(&spath_lock);

	if (!startx86_path)
		startx86_path = kzalloc(PATH_MAX, GFP_ATOMIC);
	if (!startx86_path) {
		write_unlock(&spath_lock);
		return -ENOMEM;
	}

	strscpy(startx86_path, buf, PATH_MAX);

	write_unlock(&spath_lock);

	return count;
}

static int proc_spath_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_spath_show, NULL);
}

static const struct proc_ops proc_spath_ops = {
	.proc_open	= proc_spath_open,
	.proc_read	= seq_read,
	.proc_write	= proc_spath_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static struct proc_dir_entry *bincomp_pde, *search_path_pde;

static int __init init_rtc_binfmt(void)
{
	bincomp_pde = proc_mkdir("bincomp", NULL);
	search_path_pde = proc_create("bincomp/search_path", 0, NULL, &proc_spath_ops);
	insert_binfmt(&rtc_elf_format);

	return 0;
}

late_initcall(init_rtc_binfmt);
