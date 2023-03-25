#include <linux/version.h>
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/seq_file.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>

#include "internal.h"


struct bincomp_struct {
	uint64_t version;
	uint64_t x86_mmap_addr;
};

static const struct seq_operations *proc_maps_ops;
static struct seq_operations rtcfs_maps_ops;

static const struct seq_operations *proc_smaps_ops;
static struct seq_operations rtcfs_smaps_ops;

static const struct seq_operations *proc_mounts_ops;
static struct seq_operations rtcfs_mounts_ops;

static const struct seq_operations *proc_mountinfo_ops;
static struct seq_operations rtcfs_mountinfo_ops;

static const struct seq_operations *proc_mountstats_ops;
static struct seq_operations rtcfs_mountstats_ops;

#ifdef BINCOMP_RLIM_NLIMITS
static int (*proc_limits_show)(struct seq_file *m, void *v);
#endif

/* Common function for opening seqfile */
static int rtcfs_seqfile_open_common(struct inode *inode, struct file *file,
				struct seq_operations *fake_ops,
				const struct seq_operations **orig_ops,
				int (*show)(struct seq_file *m, void *v))
{
	struct inode *proc_inode;
	struct seq_file *m;
	int res;

	proc_inode = PROC_INODE(inode);
	res = proc_inode->i_fop->open(proc_inode, file);
	if (res)
		return res;

	m = file->private_data;

	if (*orig_ops == NULL) {
		*orig_ops = m->op;
		memcpy(fake_ops, *orig_ops, sizeof(struct seq_operations));
		fake_ops->show = show;
	}
	m->op = fake_ops;
	return res;
}

/* Common function for releasing seqfile */
int rtcfs_seqfile_release(struct inode *inode, struct file *file)
{
	struct inode *proc_inode;

	proc_inode = PROC_INODE(inode);
	return proc_inode->i_fop->release(proc_inode, file);
}

/* Calculate first x86 argument's offset in a given buffer */
static size_t __rtcfs_get_x86_args_offset(const char *buf, size_t size)
{
	size_t res = 0;
	int i;

	for (i = 0; i < size; i++) {
		if (buf[i] != 0)
			continue;
		if (i+4 >= size)
			break;
		if ((buf[i+1] == '-') && (buf[i+2] == '-') && (buf[i+3] == 0)) {
			res = i + 4;
			break;
		}
	}
	return res;
}
/* Returns first x86 argument's offset in task cmdline */
static ssize_t rtcfs_get_x86_args_offset(struct task_struct *tsk,
				unsigned long arg_start, size_t size)
{
	ssize_t res;
	char *buf = kmalloc(size, GFP_KERNEL);

	if (!buf)
		return -ENOMEM;

	res = access_process_vm(tsk, arg_start, buf, size, FOLL_ANON);
	if (res <= 0)
		goto exit;

	res = __rtcfs_get_x86_args_offset(buf, res);
exit:
	kfree(buf);
	return res;
}

/* According to linux-5.4/fs/proc/base.c: get_mm_proctitle() */
static ssize_t rtcfs_get_mm_proctitle(struct task_struct *tsk, char __user *buf,
		size_t count, unsigned long pos, unsigned long arg_start)
{
	char *page;
	int ret, got;

	if (pos >= PAGE_SIZE)
		return 0;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = 0;
	got = access_process_vm(tsk, arg_start, page, PAGE_SIZE, FOLL_ANON);
	if (got > 0) {
		int len = strnlen(page, got);

		/* Include the NUL character if it was found */
		if (len < got)
			len++;

		if (len > pos) {
			len -= pos;
			if (len > count)
				len = count;
			len -= copy_to_user(buf, page+pos, len);
			if (!len)
				len = -EFAULT;
			ret = len;
		}
	}
	free_page((unsigned long)page);
	return ret;
}

/* according to linux-5.4/fs/proc/base.c: get_task_cmdline() */
static ssize_t __rtcfs_cmdline_read(struct task_struct *tsk, char __user *buf,
					size_t count, loff_t *ppos)
{
	unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long pos, len = 0;
	char *page, c;
	ssize_t offset, res = 0;
	struct mm_struct *mm;

	mm = get_task_mm(tsk);

	if (!mm)
		return 0;

	/* Check if process spawned far enough to have cmdline. */
	if (!mm->env_end)
		goto exit;

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
	spin_unlock(&mm->arg_lock);

	offset = rtcfs_get_x86_args_offset(tsk, arg_start, arg_end - arg_start);
	if (offset < 0)
		goto exit;

	arg_start += offset;

	if (arg_start >= arg_end)
		goto exit;

	/*
	 * We allow setproctitle() to overwrite the argument
	 * strings, and overflow past the original end. But
	 * only when it overflows into the environment area.
	 */
	if (env_start != arg_end || env_end < env_start) {
		env_start = arg_end;
		env_end = arg_end;
	}
	len = env_end - arg_start;

	/* We're not going to care if "*ppos" has high bits set */
	pos = *ppos;
	if (pos >= len)
		goto exit;
	if (count > len - pos)
		count = len - pos;
	if (!count)
		goto exit;

	/*
	 * Magical special case: if the argv[] end byte is not
	 * zero, the user has overwritten it with setproctitle(3).
	 */
	if (access_process_vm(tsk, arg_end-1, &c, 1, FOLL_ANON) == 1 && c) {
		res = rtcfs_get_mm_proctitle(tsk, buf, count, pos, arg_start);
		goto exit;
	}

	/*
	 * For the non-setproctitle() case we limit things strictly
	 * to the [arg_start, arg_end[ range.
	 */
	pos += arg_start;
	if (pos < arg_start || pos >= arg_end)
		goto exit;
	if (count > arg_end - pos)
		count = arg_end - pos;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		res = -ENOMEM;
		goto exit;
	}

	len = 0;
	while (count) {
		int got;
		size_t size = min_t(size_t, PAGE_SIZE, count);

		got = access_process_vm(tsk, pos, page, size, FOLL_ANON);
		if (got <= 0)
			break;

		got -= copy_to_user(buf, page, got);
		if (unlikely(!got)) {
			if (!len)
				len = -EFAULT;
			break;
		}
		pos += got;
		buf += got;
		len += got;
		count -= got;
	}

	res = len;
	free_page((unsigned long)page);
exit:
	mmput(mm);
	return res;
}

ssize_t rtcfs_cmdline_read(struct file *file, char __user *buf,
				size_t count, loff_t *pos)
{
	struct task_struct *tsk;
	struct dentry *dentry;
	struct pid_namespace *ns;
	ssize_t ret;

	BUG_ON(*pos < 0);

	dentry = file->f_path.dentry;
	ns = RTCFS_NS(dentry->d_sb);

	tsk = rtcfs_get_proc_task(dentry->d_parent, ns);
	if (!tsk)
		return -ESRCH;

	ret = __rtcfs_cmdline_read(tsk, buf, count, pos);
	put_task_struct(tsk);

	if (ret > 0)
		*pos += ret;
	return ret;
}

/* Faking maps and smaps files */
int __rtcfs_show_maps(struct seq_file *m, struct vm_area_struct *vma,
			const struct seq_operations *op)
{
	char tmp_seq_buf[4096]; /* big enough for smap entry*/
	struct seq_file tmp_seq_file;
	unsigned long start, end;
	char *hypen_p, *space_p;
	int start_len, end_len;
	char *p, addr_buf[17]; /* %llx + null*/

	memset(tmp_seq_buf, 0, 4096);
	memcpy(&tmp_seq_file, m, sizeof(struct seq_file));

	tmp_seq_file.buf   = tmp_seq_buf;
	tmp_seq_file.size  = sizeof(tmp_seq_buf);
	tmp_seq_file.count = 0;

	op->show(&tmp_seq_file, vma);
	/* tmp_seq_buf overflow shouldn't happen */
	BUG_ON(tmp_seq_file.count == tmp_seq_file.size);

	if (!ADDR_IN_SS(vma->vm_start) || !ADDR_IN_SS(vma->vm_end)) {
		/* additional field was used to go to the next record */
		m->version = tmp_seq_file.version;
		return 0;
	}

	/* m overflow case */
	if (m->count + tmp_seq_file.count >= m->size) {
		m->count = m->size;
		return 0;
	}

	m->version = tmp_seq_file.version;

	if (tmp_seq_file.count < 34) /* %llx-%llx + null*/
		return 0;

	if (sscanf(tmp_seq_buf, "%lx-%lx", &start, &end) != 2)
		return 0;

	hypen_p = strnchr(tmp_seq_buf, 17, '-'); /* %llx- */
	if (!hypen_p)
		return 0;

	space_p = strnchr(tmp_seq_buf, 34, ' '); /* %llx-%llx + space */
	if (!space_p)
		return 0;

	start_len = hypen_p - tmp_seq_buf; /* length of vma_start string */
	end_len   = space_p - hypen_p - 1; /* length of vma_end string */

	/* overwrite address in the buffer */
	snprintf(addr_buf, sizeof(addr_buf), "%016lx",
				(long)(start - SS_ADDR_START));
	p = addr_buf + sizeof(addr_buf) - 1 - start_len;
	memcpy(tmp_seq_buf, p, start_len);

	snprintf(addr_buf, sizeof(addr_buf), "%016lx",
				(long)(end - SS_ADDR_START));
	p = addr_buf + sizeof(addr_buf) - 1 - end_len;
	memcpy(hypen_p + 1, p, end_len);

	seq_printf(m, tmp_seq_buf);
	return 0;
}

static int rtcfs_show_maps(struct seq_file *m, void *v)
{
	return __rtcfs_show_maps(m, v, proc_maps_ops);
}

static int rtcfs_show_smaps(struct seq_file *m, void *v)
{
	return __rtcfs_show_maps(m, v, proc_smaps_ops);
}

int rtcfs_maps_open(struct inode *inode, struct file *file)
{
	return rtcfs_seqfile_open_common(inode, file, &rtcfs_maps_ops,
					&proc_maps_ops, rtcfs_show_maps);
}

int rtcfs_smaps_open(struct inode *inode, struct file *file)
{
	return rtcfs_seqfile_open_common(inode, file, &rtcfs_smaps_ops,
					&proc_smaps_ops, rtcfs_show_smaps);
}

/* Faking mounts, mountinfo and mountstats files */
int __rtcfs_show_mounts(struct seq_file *m, void *v,
			const struct seq_operations *op)
{
	char tmp_seq_buf[4096]; /* big enough for mount entry*/
	struct seq_file tmp_seq_file;
	int res;

	memset(tmp_seq_buf, 0, sizeof(tmp_seq_buf));
	memcpy(&tmp_seq_file, m, sizeof(struct seq_file));

	tmp_seq_file.buf   = tmp_seq_buf;
	tmp_seq_file.size  = sizeof(tmp_seq_buf);
	tmp_seq_file.count = 0;

	res = op->show(&tmp_seq_file, v);
	if (res)
		goto out;

	/* overflow case */
	BUG_ON(tmp_seq_file.count == tmp_seq_file.size);

	/* for /proc/pid/mounts and /proc/pid/mountinfo */
	char needle[] = " rtc_proc ";
	char *ptr = strstr(tmp_seq_buf, needle);

	if (!ptr) {
		/* second attempt for /proc/pid/mountstats */
		char needle[] = "fstype rtc_proc";

		ptr = strstr(tmp_seq_buf, needle);
		if (ptr)
			ptr += strlen("fstype");
	}
	/* transform 'rtc_proc' to 'proc': deleting first 4 symbols 'rtc_' */
	if (ptr) {
		while ((++ptr)[4])
			*ptr = ptr[4];
		ptr[0] = 0;
	}
out:
	seq_printf(m, tmp_seq_buf);
	return res;
}

int rtcfs_show_mounts(struct seq_file *m, void *v)
{
	return __rtcfs_show_mounts(m, v, proc_mounts_ops);
}

int rtcfs_show_mountinfo(struct seq_file *m, void *v)
{
	return __rtcfs_show_mounts(m, v, proc_mountinfo_ops);
}

int rtcfs_show_mountstats(struct seq_file *m, void *v)
{
	return __rtcfs_show_mounts(m, v, proc_mountstats_ops);
}

int rtcfs_mounts_open(struct inode *inode, struct file *file)
{
	return rtcfs_seqfile_open_common(inode, file, &rtcfs_mounts_ops,
					&proc_mounts_ops, rtcfs_show_mounts);
}

int rtcfs_mountinfo_open(struct inode *inode, struct file *file)
{
	return rtcfs_seqfile_open_common(inode, file, &rtcfs_mountinfo_ops,
				&proc_mountinfo_ops, rtcfs_show_mountinfo);
}

int rtcfs_mountstats_open(struct inode *inode, struct file *file)
{
	return rtcfs_seqfile_open_common(inode, file, &rtcfs_mountstats_ops,
				&proc_mountstats_ops, rtcfs_show_mountstats);
}

__poll_t rtcfs_mounts_poll(struct file *file, poll_table *wait)
{
	struct inode *proc_inode;
	struct file proc_file;

	proc_inode = PROC_INODE(file_inode(file));
	file_to_procfile(&proc_file, file);

	return proc_inode->i_fop->poll(&proc_file, wait);
}

/* Generating exe link path from cmdline */
static int rtcfs_get_exe_path_cmdline(struct task_struct *tsk,
				struct mm_struct *mm, struct path *exe_path)
{
	int res = -ENOENT;
	unsigned long arg_start, arg_end;
	size_t offset;
	char *page;
	struct path p;
	const char *x86_arg;

	if (!mm->env_end)
		goto exit;

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	spin_unlock(&mm->arg_lock);

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		res = -ENOMEM;
		goto exit;
	}

	res = access_process_vm(tsk, arg_start, page, PAGE_SIZE, FOLL_ANON);
	if (res <= 0) {
		res = -ENOENT;
		goto exit;
	}

	offset = __rtcfs_get_x86_args_offset(page, PAGE_SIZE);
	arg_start += offset;

	if (arg_start >= arg_end)
		goto exit;

	x86_arg = (char *)(page + offset);

	get_fs_root(tsk->fs, &p);
	res = vfs_path_lookup(p.dentry, p.mnt, x86_arg,
				LOOKUP_FOLLOW, exe_path);
	path_put(&p);
exit:
	return res;
}

#ifdef GET_BIN_COMP_INFO
/* Generating exe link path from vma */
static int rtcfs_get_exe_path_vma(struct mm_struct *mm, struct path *exe_path)
{
	int res = -ENOENT;
	struct bincomp_struct *bs;

	bs = (struct bincomp_struct *)mm->context.bincomp_info.info;
	if (bs && bs->x86_mmap_addr) {
		struct vm_area_struct *vma;

		down_read(&mm->mmap_sem);
		vma = find_vma(mm, bs->x86_mmap_addr);
		if (vma && vma->vm_file) {
			*exe_path = vma->vm_file->f_path;
			path_get(&vma->vm_file->f_path);
			res = 0;
		}
		up_read(&mm->mmap_sem);
	}
	return res;
}
#endif

static int __rtcfs_exe_get_link(struct dentry *dentry, struct path *exe_path)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct pid_namespace *ns;
	int res = -ENOENT;

	ns = RTCFS_NS(dentry->d_sb);
	tsk = rtcfs_get_proc_task(dentry->d_parent, ns);
	if (!tsk)
		return res;

	mm = get_task_mm(tsk);
	if (!mm)
		goto tput;
	read_lock(&mm->context.bincomp_info.lock);
#ifdef GET_BIN_COMP_INFO
	res = rtcfs_get_exe_path_vma(mm, exe_path);
#endif
	if (res)
		res = rtcfs_get_exe_path_cmdline(tsk, mm, exe_path);
	read_unlock(&mm->context.bincomp_info.lock);
	mmput(mm);
tput:
	put_task_struct(tsk);
	return res;
}

const char *rtcfs_exe_get_link(struct dentry *dentry, struct inode *inode,
				struct delayed_call *done)
{
	struct inode *proc_inode;
	struct dentry *proc_dentry;
	struct path path;
	int res;

	proc_dentry = PROC_DENTRY(d_inode(dentry));
	proc_inode  = PROC_INODE(d_inode(dentry));

	/* Checking if all is correct via original function */
	res = IS_ERR(proc_inode->i_op->get_link(proc_dentry, proc_inode, done));
	if (res)
		return ERR_PTR(res);

	res = __rtcfs_exe_get_link(dentry, &path);
	if (res)
		return ERR_PTR(res);

	nameidata_jump_link(&path);
	return NULL;
}

static int __rtcfs_exe_readlink(struct path *path, char __user *buffer,
				int buflen)
{
	char *tmp = (char *)__get_free_page(GFP_KERNEL);
	char *pathname;
	int len;

	if (!tmp)
		return -ENOMEM;

	pathname = d_path(path, tmp, PAGE_SIZE);
	len = PTR_ERR(pathname);
	if (IS_ERR(pathname))
		goto out;

	len = tmp + PAGE_SIZE - 1 - pathname;
	if (len > buflen)
		len = buflen;
	if (copy_to_user(buffer, pathname, len))
		len = -EFAULT;
out:
	free_page((unsigned long)tmp);
	return len;
}

int rtcfs_exe_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct path path;
	int res = -EACCES;

	res = __rtcfs_exe_get_link(dentry, &path);

	if (res)
		goto out;

	res = __rtcfs_exe_readlink(&path, buffer, buflen);
	path_put(&path);
out:
	return res;
}

#ifdef BINCOMP_RLIM_NLIMITS
static const char *lnames[BINCOMP_RLIM_NLIMITS] = {
	"Max data size",
	"Max stack size",
	"Max address space",
};

static void rtcfs_print_bincomp_limit(char *buf, struct rlimit *rlim,
						size_t buf_size)
{
	int i;
	size_t nsyms;

	for (i = 0; i < BINCOMP_RLIM_NLIMITS; i++)
		if (!strncmp(lnames[i], buf, min(sizeof(lnames[i]), buf_size)))
			break;

	if (i == BINCOMP_RLIM_NLIMITS)
		return;

	if (rlim[i].rlim_cur == RLIM_INFINITY)
		nsyms = snprintf(buf, buf_size, "%-25s %-21s",
						lnames[i], "unlimited");
	else
		nsyms = snprintf(buf, buf_size, "%-25s %-21lu",
						lnames[i], rlim[i].rlim_cur);

	if (rlim[i].rlim_max == RLIM_INFINITY)
		nsyms += snprintf(buf + nsyms, buf_size, "%-20s %-10s",
						"unlimited", "bytes");
	else
		nsyms += snprintf(buf + nsyms, buf_size, "%-20lu %-10s",
						rlim[i].rlim_max, "bytes");
	buf[nsyms] = '\n';
}

int rtcfs_show_limits(struct seq_file *m, void *v)
{
	struct file *file;
	struct inode *inode;
	struct dentry *dentry;
	struct task_struct *tsk;
	char tmp_seq_buf[4096]; /* big enough for limits file*/
	struct seq_file tmp_seq_file;
	unsigned long flags;
	struct rlimit rlim[BINCOMP_RLIM_NLIMITS];
	char *pos, *str_end;
	int res = 0;

	file   = m->private;
	inode  = file->f_inode;
	dentry = file->f_path.dentry;
	tsk = rtcfs_get_proc_task(dentry->d_parent, RTCFS_NS(dentry->d_sb));
	if (!tsk)
		goto out;

	/* getting x86 rlimits */
	spin_lock_irqsave(&tsk->sighand->siglock, flags);
	memcpy(rlim, tsk->signal->bin_comp_rlim,
		sizeof(struct rlimit) * BINCOMP_RLIM_NLIMITS);
	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);
	put_task_struct(tsk);

	/* constructing fake file */
	memset(tmp_seq_buf, 0, sizeof(tmp_seq_buf));
	memcpy(&tmp_seq_file, m, sizeof(struct seq_file));
	tmp_seq_file.buf     = tmp_seq_buf;
	tmp_seq_file.size    = sizeof(tmp_seq_buf);
	tmp_seq_file.count   = 0;
	/* proc expects original inode here */
	tmp_seq_file.private = PROC_INODE(inode);

	/* calling original function */
	res = proc_limits_show(&tmp_seq_file, v);
	if (res)
		goto out;

	/* overflow case */
	BUG_ON(tmp_seq_file.count == tmp_seq_file.size);

	pos = tmp_seq_buf;
	while (pos < tmp_seq_buf + sizeof(tmp_seq_buf) && *pos)	{
		str_end = strnchr(pos, sizeof(tmp_seq_buf), '\n');
		if (!str_end)
			break;
		rtcfs_print_bincomp_limit(pos, rlim, str_end - pos + 1);
		pos = str_end + 1;
	}

out:
	seq_printf(m, tmp_seq_buf);
	return res;
}

int rtcfs_limits_open(struct inode *inode, struct file *file)
{
	struct inode *proc_inode;
	struct seq_operations *op;
	struct seq_file *m;
	int res;

	proc_inode = PROC_INODE(inode);
	/**
	 * Default open() function for "limits" file is single_open().
	 * It allocates struct seq_operations dynamically and calls kfree()
	 * on release.
	 */
	res = proc_inode->i_fop->open(proc_inode, file);
	if (res)
		return res;

	m = file->private_data;
	/**
	 * We have to save original pointer to show() function
	 * before override it.
	 */
	if (!proc_limits_show)
		proc_limits_show = m->op->show;

	op = (struct seq_operations *)m->op;
	op->show  = rtcfs_show_limits;

	m->private = file;  /* for easy dentry search */
	return res;
}
#endif
