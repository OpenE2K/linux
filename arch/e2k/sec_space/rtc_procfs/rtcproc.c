/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/seq_file.h>
#include <linux/namei.h>

#include "internal.h"
#include "files.h"


struct task_struct *rtcfs_get_proc_task(const char *name,
					struct pid_namespace *ns)
{
	struct pid *pid_struct;
	struct task_struct *tsk;
	int pid, res;

	res = kstrtoint(name, 10, &pid);
	if (res)
		return NULL;

	rcu_read_lock();
	pid_struct = find_pid_ns(pid, ns);
	if (!pid_struct) {
		rcu_read_unlock();
		return NULL;
	}
	tsk = get_pid_task(pid_struct, PIDTYPE_PID);
	rcu_read_unlock();

	return tsk;
}

static int rtcfs_is_serving_thread(struct task_struct *tsk)
{
	return task_thread_info(tsk)->bc_flags & BC_IS_SERVING;
}

/* Duplicate proc inode in our cache */
struct inode *rtcfs_duplicate_proc_inode(struct super_block *sb,
					const struct path *path)
{
	struct inode *i;
	struct inode *proc_inode;

	i = new_inode(sb);
	if (!i)
		goto out;

	RTCFS_I(i)->dentry	= path->dentry;
	dget(PROC_DENTRY(i));

	proc_inode	= PROC_INODE(i);
	spin_lock(&proc_inode->i_lock);
	i->i_mode	= proc_inode->i_mode;
	i->i_opflags	= proc_inode->i_opflags;
	i->i_uid	= proc_inode->i_uid;
	i->i_gid	= proc_inode->i_gid;
	i->i_flags	= proc_inode->i_flags;
	i->i_ino	= proc_inode->i_ino;
	i->i_rdev	= proc_inode->i_rdev;
	i->i_size	= proc_inode->i_size;
	i->i_atime	= proc_inode->i_atime;
	i->i_mtime	= proc_inode->i_mtime;
	i->i_ctime	= proc_inode->i_ctime;
	spin_unlock(&proc_inode->i_lock);

out:
	path_put(path);
	return i;
}

static int rtcfs_delete_dentry(const struct dentry *dentry)
{
	/* Disabling dcache */
	return 1;
}

const struct dentry_operations rtcfs_dentry_operations = {
	.d_delete    = rtcfs_delete_dentry,
};

/**
 * Adding rtc_proc dentry for existing [proc] inode.
 * When return original procfs dentry, d_parent will contain address of real
 * procfs parent. may_delete() checks correctness of d_parent pointer. We have
 * to produce our own dentries for files.
 */
static struct dentry *rtcfs_allocacte_dentry_for_inode(struct dentry *dentry,
						const struct path *proc_path)
{
	struct inode *inode;

	inode = igrab(d_inode(proc_path->dentry));
	path_put(proc_path);
	if (!inode)
		return NULL;

	d_set_d_op(dentry, &rtcfs_dentry_operations);
	return d_splice_alias(inode, dentry);
}

/**
 * Duplicating proc inode in rtcfs cache and tuning it's operations.
 * struct path reference count should be incremented!
 * struct path will be released on inode's freeing.
 */
static struct dentry *rtcfs_allocate_object(struct dentry *dentry,
					const struct path *proc_path,
					const struct file_operations *fop,
					const struct inode_operations *op)
{
	struct inode *inode;

	inode = rtcfs_duplicate_proc_inode(dentry->d_sb, proc_path);
	if (!inode)
		return NULL;
	inode->i_fop = fop;
	inode->i_op  = op;

	d_set_d_op(dentry, &rtcfs_dentry_operations);
	return d_splice_alias(inode, dentry);
}

/* Common part for directory lookup */
static int __rtcfs_dir_lookup(struct inode *dir, struct dentry *dentry,
						struct path *path)
{
	struct dentry *parent	= PROC_DENTRY(dir);
	struct rtcfs_sb_info *sbi = RTCFS_SBI(dentry->d_sb);

	return vfs_path_lookup(parent, sbi->proc_mnt,
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
	struct path  proc_path;
	struct inode *proc_inode;
	struct rtcfs_sb_info *sbi = RTCFS_SBI(path->dentry->d_sb);

	proc_path.dentry	= PROC_DENTRY(d_inode(path->dentry));
	proc_path.mnt		= sbi->proc_mnt;
	proc_inode = PROC_INODE(d_inode(path->dentry));
	return proc_inode->i_op->getattr(&proc_path, stat,
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

/* Filter that allows us to hide binary compiler serving threads */
static int rtcfs_actor_filter(struct dir_context *ctx, const char *name,
		int namelen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct task_struct *tsk;
	struct pid_namespace *ns;
	struct rtcfs_dir_context *c;
	int is_serving_thread = 0;

	c = container_of(ctx, struct rtcfs_dir_context, ctx);
	ns = RTCFS_NS(c->file->f_path.dentry->d_sb);

	if (!S_ISDIR(c->file->f_inode->i_mode))
		goto exit;

	tsk = rtcfs_get_proc_task(name, ns);
	if (!tsk)
		goto exit;

	if (TASK_IS_BINCO(tsk))
		is_serving_thread = rtcfs_is_serving_thread(tsk);

	put_task_struct(tsk);

exit:
	return is_serving_thread ?
			0 : c->proc_ctx->actor(c->proc_ctx, name, namelen, offset, ino, d_type);
}

int rtcfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *proc_inode;
	struct file proc_file;
	struct rtcfs_dir_context rtcfs_ctx;
	int res;

	rtcfs_ctx.file		 = file;
	rtcfs_ctx.proc_ctx	 = ctx;
	rtcfs_ctx.ctx.actor  = rtcfs_actor_filter;
	rtcfs_ctx.ctx.pos    = ctx->pos;

	proc_inode = PROC_INODE(file_inode(file));
	file_to_procfile(&proc_file, file);

	res = proc_inode->i_fop->iterate_shared(&proc_file, &rtcfs_ctx.ctx);
	ctx->pos = rtcfs_ctx.ctx.pos;
	return res;
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

	return rtcfs_allocate_object(dentry, &file_path,
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

static const struct file_operations limits_ops = {
	.open       = rtcfs_limits_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = rtcfs_seqfile_release,
};

static const struct file_operations pagemap_ops = {
	.llseek		= rtcfs_mem_lseek, /* borrow this */
	.read		= rtcfs_pagemap_read,
	.open		= rtcfs_pagemap_open,
	.release	= rtcfs_pagemap_release,
};

static const struct file_operations cpuinfo_ops = {
	.open		= rtcfs_cpuinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* Allocating objects for /rtc_proc/pid/ and /rtc_proc/pid/task/tid if exists */
static struct dentry *rtcfs_pid_tid_lookup(struct inode *dir,
				struct dentry *dentry, unsigned int flags)
{
	struct path file_path;
	struct dentry *res_dentry;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	if (!strcmp(dentry->d_name.name, "task"))
		return rtcfs_allocate_object(dentry, &file_path,
					&task_file_op, &task_inode_op);
	else if (!strcmp(dentry->d_name.name, "maps"))
		return rtcfs_allocate_object(dentry, &file_path,
					&maps_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "smaps"))
		return rtcfs_allocate_object(dentry, &file_path,
					&smaps_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "cmdline"))
		return rtcfs_allocate_object(dentry, &file_path,
					&cmdline_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mounts"))
		return rtcfs_allocate_object(dentry, &file_path,
					&mounts_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mountinfo"))
		return rtcfs_allocate_object(dentry, &file_path,
					&mountinfo_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "mountstats"))
		return rtcfs_allocate_object(dentry, &file_path,
					&mountstats_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "exe"))
		return rtcfs_allocate_object(dentry, &file_path,
					NULL, &exe_ops);
	else if (!strcmp(dentry->d_name.name, "limits"))
		return rtcfs_allocate_object(dentry, &file_path,
					&limits_ops, &rtcfs_def_inode_ops);
	else if (!strcmp(dentry->d_name.name, "pagemap"))
		return rtcfs_allocate_object(dentry, &file_path,
					&pagemap_ops, &rtcfs_def_inode_ops);

	if (!S_ISDIR(d_inode(file_path.dentry)->i_mode))
		return rtcfs_allocacte_dentry_for_inode(dentry,
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

struct dentry *rtcfs_root_lookup(struct inode *dir, struct dentry *dentry,
							unsigned int flags)
{
	struct path file_path;
	struct pid_namespace *ns;
	struct dentry *res_dentry;
	struct task_struct *tsk;
	bool is_binco, is_serving_thread;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	if (!strcmp(dentry->d_name.name, "cpuinfo"))
		return rtcfs_allocate_object(dentry, &file_path,
					&cpuinfo_ops, &rtcfs_def_inode_ops);

	ns = RTCFS_NS(dentry->d_sb);
	tsk = rtcfs_get_proc_task(file_path.dentry->d_name.name, ns);
	if (!tsk)
		goto ret_orig;

	is_binco = TASK_IS_BINCO(tsk);
	is_serving_thread = is_binco ? rtcfs_is_serving_thread(tsk) : 0;
	put_task_struct(tsk);

	/* Hide serving threads */
	if (is_serving_thread) {
		res_dentry = NULL;
		goto out_put;
	}

	if (is_binco)
		return rtcfs_allocate_object(dentry, &file_path,
						&pid_file_op, &pid_inode_op);

ret_orig:
	if (!S_ISDIR(d_inode(file_path.dentry)->i_mode))
		return rtcfs_allocacte_dentry_for_inode(dentry,	&file_path);
	/* Returning original procfs dentry. struct path should be released */
	res_dentry = file_path.dentry;
	dget(res_dentry);
out_put:
	path_put(&file_path);
	return res_dentry;
}
