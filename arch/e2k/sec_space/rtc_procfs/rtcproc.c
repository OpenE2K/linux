#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/kprobes.h>

#include "internal.h"
#include "files.h"

nd_jump_link_t nameidata_jump_link;

struct task_struct *rtcfs_get_proc_task(struct dentry *dentry,
					struct pid_namespace *ns)
{
	struct pid *pid_struct;
	int pid, res;
	const char *name;

	if (!dentry || !ns)
		return NULL;
	name = dentry->d_name.name;
	res = kstrtoint(name, 10, &pid);
	if (res)
		return NULL;

	pid_struct = find_pid_ns(pid, ns);
	if (!pid_struct)
		return NULL;
	return get_pid_task(pid_struct, PIDTYPE_PID);
}

/* Duplicate proc inode in our cache */
struct inode *rtcfs_duplicate_proc_inode(struct super_block *sb,
					const struct path *path)
{
	struct inode *i;
	struct inode *proc_inode;

	i = new_inode(sb);
	if (!i) {
		path_put(path);
		return NULL;
	}

	memcpy(PROC_PATH(i), path, sizeof(struct path));
	proc_inode = PROC_INODE(i);
	i->i_mode  = proc_inode->i_mode;
	i->i_atime = proc_inode->i_atime;
	i->i_mtime = proc_inode->i_mtime;
	i->i_ctime = proc_inode->i_ctime;
	i->i_ino   = proc_inode->i_ino;
	i->i_mtime = proc_inode->i_mtime;
	i->i_uid   = proc_inode->i_uid;
	i->i_gid   = proc_inode->i_gid;
	return i;
}

int rtcfs_delete_dentry(const struct dentry *dentry)
{
	/* Disabling dcache */
	return 1;
}

const struct dentry_operations rtcfs_dentry_operations = {
	.d_delete    = rtcfs_delete_dentry,
};

/* Allocating a dentry, pointing to an existing inode */
static struct dentry *rtcfs_alloc_bind_dentry(struct dentry *parent,
					const struct dentry *proc_dentry,
					struct inode *inode)
{
	struct dentry *dentry;

	dentry = d_alloc_name(parent, proc_dentry->d_name.name);
	if (!dentry)
		return NULL;

	d_set_d_op(dentry, &rtcfs_dentry_operations);
	d_add(dentry, inode);
	return dentry;
}

/**
 * Adding rtc_proc dentry for existing [proc] inode.
 * When return original procfs dentry, d_parent will contain address of real
 * procfs parent. may_delete() checks correctness of d_parent pointer. We have
 * to produce our own dentries for files.
 */
static struct dentry *rtcfs_allocacte_dentry_for_inode(struct dentry *parent,
						const struct path *proc_path)
{
	struct inode *inode;

	inode = igrab(d_inode(proc_path->dentry));
	if (!inode)
		return NULL;
	return rtcfs_alloc_bind_dentry(parent, proc_path->dentry, inode);
}

/**
 * Duplicating proc inode in rtcfs cache and tuning it's operations
 * struct path reference count should be incremented!
 * struct path will be released on inode's freeing.
 */
static struct dentry *rtcfs_allocate_object(struct dentry *parent,
					const struct path *proc_path,
					const struct file_operations *fop,
					const struct inode_operations *op)
{
	struct inode *inode;
	struct dentry *dentry;

	inode = rtcfs_duplicate_proc_inode(parent->d_sb, proc_path);
	if (!inode)
		return NULL;

	inode->i_fop = fop;
	inode->i_op  = op;

	dentry = rtcfs_alloc_bind_dentry(parent, proc_path->dentry, inode);
	if (!dentry)
		iput(inode);

	return dentry;
}

/* Common part for directory lookup */
static int __rtcfs_dir_lookup(struct inode *dir, struct dentry *dentry,
						struct path *path)
{
	struct path  *parent;
	struct inode *proc_inode;

	parent     = PROC_PATH(dir);
	proc_inode = PROC_INODE(dir);
	return vfs_path_lookup(parent->dentry, parent->mnt,
				dentry->d_name.name, 0, path);
}

static int rtcfs_permission(struct inode *inode, int mask)
{
	struct inode *proc_inode;

	proc_inode = PROC_INODE(inode);
	return proc_inode->i_op->permission(proc_inode, mask);
}

int rtcfs_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int query_flags)
{
	struct path  *proc_path;
	struct inode *proc_inode;

	proc_path  = PROC_PATH(d_inode(path->dentry));
	proc_inode = PROC_INODE(d_inode(path->dentry));
	return proc_inode->i_op->getattr(proc_path, stat,
					request_mask, query_flags);
}

static int rtcfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct dentry *proc_dentry;
	struct inode *proc_inode;

	proc_dentry = PROC_DENTRY(d_inode(dentry));
	proc_inode  = PROC_INODE(d_inode(dentry));
	return proc_inode->i_op->setattr(proc_dentry, attr);
}

int rtcfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *proc_inode;
	struct file proc_file;

	proc_inode = PROC_INODE(file_inode(file));
	file_to_procfile(&proc_file, file);

	return proc_inode->i_fop->iterate_shared(&proc_file, ctx);
}

static struct dentry *rtcfs_pid_tid_lookup(struct inode *dir,
			struct dentry *dentry, unsigned int flags);

static const struct inode_operations task_tid_inode_op = {
	.lookup     = rtcfs_pid_tid_lookup,
	.getattr    = rtcfs_getattr,
	.setattr    = rtcfs_setattr,
};

static const struct file_operations task_tid_file_op = {
	.read           = generic_read_dir,
	.iterate_shared = rtcfs_readdir,
	.llseek         = generic_file_llseek,
};

/* Allocating /rtc_proc/pid/task if exists */
struct dentry *rtcfs_task_lookup(struct inode *dir, struct dentry *dentry,
							unsigned int flags)
{
	/*
	 * If we are here, task belongs to the binary compiler.
	 * Allocating object unconditionally, if it exists.
	 */
	struct path file_path;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	return rtcfs_allocate_object(dentry->d_parent, &file_path,
				&task_tid_file_op, &task_tid_inode_op);
}

static const struct inode_operations rtcfs_def_inode_ops = {
	.setattr    = rtcfs_setattr,
};

static const struct inode_operations task_inode_op = {
	.lookup     = rtcfs_task_lookup,
	.getattr    = rtcfs_getattr,
	.setattr    = rtcfs_setattr,
	.permission = rtcfs_permission,
};

static const struct file_operations task_file_op = {
	.read           = generic_read_dir,
	.iterate_shared = rtcfs_readdir,
	.llseek         = generic_file_llseek,
};

static const struct file_operations maps_ops = {
	.open    = rtcfs_maps_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = rtcfs_seqfile_release,
};

static const struct file_operations smaps_ops = {
	.open       = rtcfs_smaps_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = rtcfs_seqfile_release,
};

static const struct file_operations cmdline_ops = {
	.read   = rtcfs_cmdline_read,
	.llseek = generic_file_llseek,
};

static const struct file_operations mounts_ops = {
	.open    = rtcfs_mounts_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = rtcfs_seqfile_release,
	.poll    = rtcfs_mounts_poll,
};

static const struct file_operations mountinfo_ops = {
	.open    = rtcfs_mountinfo_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = rtcfs_seqfile_release,
	.poll    = rtcfs_mounts_poll,
};

static const struct file_operations mountstats_ops = {
	.open    = rtcfs_mountstats_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = rtcfs_seqfile_release,
};

static const struct inode_operations exe_ops = {
	.readlink = rtcfs_exe_readlink,
	.get_link = rtcfs_exe_get_link,
	.setattr  = rtcfs_setattr,
};

#ifdef BINCOMP_RLIM_NLIMITS
static const struct file_operations limits_ops = {
	.open       = rtcfs_limits_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = rtcfs_seqfile_release,
};
#endif

/* Allocating objects for /rtc_proc/pid/ and /rtc_proc/pid/task/tid if exists */
static struct dentry *rtcfs_pid_tid_lookup(struct inode *dir,
				struct dentry *dentry, unsigned int flags)
{
	struct path file_path;
	struct dentry *res_dentry;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	if (!strcmp(dentry->d_name.name, "task"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&task_file_op, &task_inode_op);
	else if (!strcmp(dentry->d_name.name, "maps"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&maps_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "smaps"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&smaps_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "cmdline"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&cmdline_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mounts"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&mounts_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mountinfo"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&mountinfo_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mountstats"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&mountstats_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "exe"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					NULL, &exe_ops);
#ifdef BINCOMP_RLIM_NLIMITS
	else if (!strcmp(dentry->d_name.name, "limits"))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
					&limits_ops, &rtcfs_def_inode_ops);
#endif
	else if (!S_ISDIR(d_inode(file_path.dentry)->i_mode))
		return rtcfs_allocacte_dentry_for_inode(dentry->d_parent,
					&file_path);

	/* Returning original procfs dentry -> struct path should be released */
	res_dentry = file_path.dentry;
	dget(res_dentry);
	path_put(&file_path);
	return res_dentry;
}

static const struct inode_operations pid_inode_op = {
	.lookup     = rtcfs_pid_tid_lookup,
	.getattr    = rtcfs_getattr,
	.setattr    = rtcfs_setattr,
	.permission = rtcfs_permission,
};

static const struct file_operations pid_file_op = {
	.read           = generic_read_dir,
	.iterate_shared = rtcfs_readdir,
	.llseek         = generic_file_llseek,
};

static bool is_bincomp_pid(struct dentry *dentry, struct pid_namespace *ns)
{
	struct task_struct *tsk;
	int res;

	tsk = rtcfs_get_proc_task(dentry, ns);
	if (!tsk)
		return false;

	res = TASK_IS_BINCO(tsk);
	put_task_struct(tsk);
	return res;
}

struct dentry *rtcfs_root_lookup(struct inode *dir, struct dentry *dentry,
							unsigned int flags)
{
	struct path file_path;
	struct pid_namespace *ns;
	struct dentry *res_dentry;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	ns = RTCFS_NS(dentry->d_sb);
	if (is_bincomp_pid(file_path.dentry, ns))
		return rtcfs_allocate_object(dentry->d_parent, &file_path,
						&pid_file_op, &pid_inode_op);

	if (!S_ISDIR(d_inode(file_path.dentry)->i_mode))
		return rtcfs_allocacte_dentry_for_inode(dentry->d_parent,
								&file_path);

	/* Returning original procfs dentry -> struct path should be released */
	res_dentry = file_path.dentry;
	dget(res_dentry);
	path_put(&file_path);
	return res_dentry;
}

static struct kprobe nd_jump_link_kp = {
	.symbol_name = "nd_jump_link"
};

int __init rtcfs_init_op(void)
{
	int ret;

	ret = register_kprobe(&nd_jump_link_kp);
	if (ret)
		return ret;

	nameidata_jump_link = (void *)nd_jump_link_kp.addr;
	unregister_kprobe(&nd_jump_link_kp);
	if (!nameidata_jump_link) {
		pr_err("Unable to find nd_jump_link\n");
		return -EFAULT;
	}
	return ret;
}
