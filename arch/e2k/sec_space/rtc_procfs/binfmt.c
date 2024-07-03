/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>


static char *startx86_path;
static DEFINE_RWLOCK(spath_lock);

/* configuring exe file for rtc_proc filesystem */
static int rtcfs_set_exe_file(bin_comp_info_t *bi, struct file *x86_exe)
{
	int res = 0;

	res = deny_write_access(x86_exe);
	if (res)
		return res;

	if (bi->exe_file) {
		/* releasing old file */
		allow_write_access(bi->exe_file);
		fput(bi->exe_file);
	}
	bi->exe_file = x86_exe;
	get_file(x86_exe);

	return res;
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

	if (check_add_overflow((u64)info, args_offsets_offset,
			&argv_off) || argv_off != (uintptr_t)argv_off)
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

static int exec_from_native(struct linux_binprm *bprm)
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
		pr_warn("Unable to open executable file '%s', err %d\n", startx86_path, ret);
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

static int exec_from_bincomp(struct linux_binprm *bprm, bool is_x64)
{
	bin_comp_info_t *bi;
	struct file *bincomp_file, *x86_exe;
	union bincomp_info_header *hdr;
	void *bi_info;
	size_t bi_info_size;
	int ret;

	bi = &bprm->mm->context.bincomp_info;

	read_lock(&bi->lock);

	/* binary compiler should be already opened */
	bincomp_file = is_x64 ? bi->rtc64 : bi->rtc32;

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

	ret = add_bincomp_args(bprm, bi_info, bi_info_size,
				hdr->v0.args_offsets_offset);
	kfree(bi_info);

	if (ret)
		goto out;

	x86_exe = bprm->file;

	/* mark the bprm that fd should be passed to interp */
	bprm->interpreter = bincomp_file;
	bprm->have_execfd = 1;
	bprm->execfd_creds = 1;

	ret = deny_write_access(bincomp_file);
	if (ret)
		goto out;

	/* store ref to file (rtc_proc's) /proc/<pid>/exe symlink points to */
	write_lock(&bi->lock);
	ret = rtcfs_set_exe_file(bi, x86_exe);
	write_unlock(&bi->lock);

	if (ret) {
		allow_write_access(bincomp_file);
		goto out;
	}

	would_dump(bprm, x86_exe);
	get_file(bincomp_file);

out:
	return ret;

out_unlock:
	read_unlock(&bi->lock);
	return ret;
}

/* Preparing bprm before binfmt_elf processes this execve */
static int load_rtc(struct linux_binprm *bprm)
{
	struct elfhdr *elf_ex;
	bool is_x64;

	elf_ex = (struct elfhdr *)bprm->buf;

	if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0 ||
			elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN ||
			elf_ex->e_machine != EM_X86_64 && elf_ex->e_machine != EM_386)
		return -ENOEXEC;

	if (WARN_ON_ONCE(!S_ISREG(file_inode(bprm->file)->i_mode) ||
			 path_noexec(&bprm->file->f_path)))
		return -EACCES;

	if (!TASK_IS_BINCO(current))
		return exec_from_native(bprm);

	is_x64 = elf_ex->e_ident[EI_CLASS] == ELFCLASS64;

	return exec_from_bincomp(bprm, is_x64);
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
		startx86_path = kzalloc(PATH_MAX, GFP_KERNEL);
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

static struct linux_binfmt rtc_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_rtc,
};

static const struct proc_ops proc_spath_ops = {
	.proc_open	= proc_spath_open,
	.proc_read	= seq_read,
	.proc_write	= proc_spath_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

struct proc_dir_entry *bincomp_pde, *search_path_pde;

int __init init_rtc_binfmt(void)
{
	bincomp_pde = proc_mkdir("bincomp", NULL);
	search_path_pde = proc_create("bincomp/search_path", 0, NULL, &proc_spath_ops);
	insert_binfmt(&rtc_format);

	return 0;
}

void __exit exit_rtc_binfmt(void)
{
	unregister_binfmt(&rtc_format);
	proc_remove(search_path_pde);
	proc_remove(bincomp_pde);
	kfree(startx86_path);
	startx86_path = 0;
}
