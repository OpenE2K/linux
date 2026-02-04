/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/stat.h>
#include <linux/dcache.h>

#include "internal.h"
#include "wrappers.h"

/**
 * This file provides wrappers for the original procfs file and inode operations.
 */

/* Inode operations */
struct dentry *rtcfs_proc_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct path file_path;

	if (__rtcfs_dir_lookup(dir, dentry, &file_path))
		return NULL;

	return rtcfs_allocate_object(dentry, &file_path, NULL, NULL);
}

static const char *rtcfs_proc_get_link(struct dentry *dentry,
				struct inode *inode, struct delayed_call *call)
{
	struct inode *proc_inode;

	if (!dentry)
		return ERR_PTR(-ECHILD);
	proc_inode = PROC_INODE(d_inode(dentry));

	return proc_inode->i_op->get_link(PROC_DENTRY(d_inode(dentry)), proc_inode, call);

}

int rtcfs_proc_permission(struct user_namespace *mnt_userns,
			    struct inode *inode, int mask)
{
	struct inode *proc_inode = PROC_INODE(inode);

	return proc_inode->i_op->permission(mnt_userns, proc_inode, mask);
}

static int rtcfs_proc_readlink(struct dentry *dentry, char __user *buf, int size)
{
	struct inode *proc_inode = PROC_INODE(d_inode(dentry));

	return proc_inode->i_op->readlink(PROC_DENTRY(d_inode(dentry)), buf, size);
}

int rtcfs_proc_getattr(struct user_namespace *mnt_userns, const struct path *path,
		  struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
	struct path  proc_path;
	struct inode *proc_inode;
	struct rtcfs_sb_info *sbi = RTCFS_SBI(path->dentry->d_sb);

	proc_path.dentry	= PROC_DENTRY(d_inode(path->dentry));
	proc_path.mnt		= sbi->proc_mnt;
	proc_inode		= PROC_INODE(d_inode(path->dentry));

	return proc_inode->i_op->getattr(mnt_userns, &proc_path, stat,
					request_mask, query_flags);
}

int rtcfs_proc_setattr(struct user_namespace *mnt_userns,
			 struct dentry *dentry, struct iattr *attr)
{
	struct dentry *proc_dentry;
	struct inode *proc_inode;

	proc_dentry = PROC_DENTRY(d_inode(dentry));
	proc_inode  = PROC_INODE(d_inode(dentry));
	return proc_inode->i_op->setattr(mnt_userns, proc_dentry, attr);
}

/* File operations */
#define RTCFS_ARG_DECL(t, a)	t a
#define RTCFS_ARG(t, a)		a

#define RTCFS_MAP_ARGS1(m, t, a, ...) m(t, a)
#define RTCFS_MAP_ARGS2(m, t, a, ...) m(t, a), RTCFS_MAP_ARGS1(m, __VA_ARGS__)
#define RTCFS_MAP_ARGS3(m, t, a, ...) m(t, a), RTCFS_MAP_ARGS2(m, __VA_ARGS__)
#define RTCFS_MAP_ARGS4(m, t, a, ...) m(t, a), RTCFS_MAP_ARGS3(m, __VA_ARGS__)
#define RTCFS_MAP_ARGS5(m, t, a, ...) m(t, a), RTCFS_MAP_ARGS4(m, __VA_ARGS__)

#define RTCFS_MAP_ARGS(__n, ...) RTCFS_MAP_ARGS##__n(__VA_ARGS__)

#define RTCFS_FILE_WRAPPER_DEFINEn(__n, __name, __rtype, ...)				\
__rtype rtcfs_proc_##__name(RTCFS_MAP_ARGS(__n, RTCFS_ARG_DECL, __VA_ARGS__))		\
{											\
	struct inode *proc_inode, *inode;						\
	struct file *orig_file;								\
	__rtype res;									\
											\
	orig_file = file;								\
	inode = file_inode(file);							\
	proc_inode = PROC_INODE(inode);							\
	file = (struct file *)orig_file->private_data;					\
	res = proc_inode->i_fop->__name(RTCFS_MAP_ARGS(__n, RTCFS_ARG, __VA_ARGS__));	\
	orig_file->f_pos = file->f_pos;							\
	return res;									\
}

#define RTCFS_IOCB_WRAPPER_DEFINEn(__n, __name, __rtype, ...)				\
__rtype rtcfs_proc_##__name(RTCFS_MAP_ARGS(__n, RTCFS_ARG_DECL, __VA_ARGS__))		\
{											\
	struct inode *proc_inode, *inode;						\
	struct file *proc_file, *file;							\
	__rtype res;									\
											\
	file = iocb->ki_filp;								\
	inode = file_inode(file);							\
											\
	proc_inode = PROC_INODE(inode);							\
	proc_file = (struct file *)file->private_data;					\
											\
	iocb->ki_filp = proc_file;							\
	res = proc_inode->i_fop->__name(RTCFS_MAP_ARGS(__n, RTCFS_ARG, __VA_ARGS__));	\
	iocb->ki_filp = file;								\
	return res;									\
}

#define RTCFS_WRAPPER_DEFINE2(__f, __name, ...) RTCFS##__f##_WRAPPER_DEFINEn(2, __name, __VA_ARGS__)
#define RTCFS_WRAPPER_DEFINE3(__f, __name, ...) RTCFS##__f##_WRAPPER_DEFINEn(3, __name, __VA_ARGS__)
#define RTCFS_WRAPPER_DEFINE4(__f, __name, ...) RTCFS##__f##_WRAPPER_DEFINEn(4, __name, __VA_ARGS__)
#define RTCFS_WRAPPER_DEFINE5(__f, __name, ...) RTCFS##__f##_WRAPPER_DEFINEn(5, __name, __VA_ARGS__)

RTCFS_WRAPPER_DEFINE3(_FILE, llseek, loff_t,
			struct file *,	file,
			loff_t,		off,
			int,		whence);
RTCFS_WRAPPER_DEFINE4(_FILE, read, ssize_t,
			struct file *,	file,
			char __user *,	buf,
			size_t,		size,
			loff_t *,	off);
RTCFS_WRAPPER_DEFINE4(_FILE, write, ssize_t,
			struct file *,		file,
			const char __user *,	buf,
			size_t,			size,
			loff_t *,		off);
RTCFS_WRAPPER_DEFINE2(_IOCB, read_iter, ssize_t,
			struct kiocb *,		iocb,
			struct iov_iter *,	iter);
static RTCFS_WRAPPER_DEFINE2(_IOCB, write_iter, ssize_t,
				struct kiocb *,		iocb,
				struct iov_iter *,	iter);
static RTCFS_WRAPPER_DEFINE3(_IOCB, iopoll, int,
				struct kiocb *,		iocb,
				struct io_comp_batch *,	batch,
				unsigned int,		flags);
static RTCFS_WRAPPER_DEFINE2(_FILE, iterate_shared, int,
				struct file *,		file,
				struct dir_context *,	ctx);
RTCFS_WRAPPER_DEFINE2(_FILE, poll, __poll_t,
			struct file *,			file,
			struct poll_table_struct *,	pts);
RTCFS_WRAPPER_DEFINE3(_FILE, unlocked_ioctl, long,
			struct file *,		file,
			unsigned int,		cmd,
			unsigned long,		arg);
static RTCFS_WRAPPER_DEFINE3(_FILE, compat_ioctl, long,
				struct file *,	file,
				unsigned int,	cmd,
				unsigned long,	arg);
RTCFS_WRAPPER_DEFINE2(_FILE, mmap, int,
			struct file *,			file,
			struct vm_area_struct *,	vma);
/**
 * rtcfs_proc's files usually are just holding a pointer to
 * the original procfs struct file. User data may be filled using
 * rtcfs_proc_*() functions, and, if it's reqired, changed before
 * it's copied to user.
 *
 * This function opens struct file in the procfs and saves the pointer
 * at rtcfs_file->private_data. Caller must release the procfs file with
 * rtcfs_proc_release().
 */
int rtcfs_proc_open(struct inode *inode, struct file *rtcfs_file)
{
	struct inode *proc_inode;
	struct path proc_path;
	struct file *proc_file;

	proc_file = (struct file *)rtcfs_file->private_data;

	if (WARN_ON_ONCE(proc_file)) /* proc_file hasn't been opened yet */
		return 0;

	proc_inode = PROC_INODE(inode);
	proc_path.dentry = PROC_DENTRY(inode);
	proc_path.mnt = RTCFS_SBI(inode->i_sb)->proc_mnt;

	/* Allocate struct file and open procfs path */
	proc_file = open_with_fake_path(&proc_path, rtcfs_file->f_flags,
					proc_inode, rtcfs_file->f_cred);
	if (IS_ERR(proc_file))
		return PTR_ERR(proc_file);

	rtcfs_file->private_data = proc_file;
	/*
	 * f_mode can be used to determine allowed file operations
	 * (and which may be not NULL, see nonseekable_open()
	 */
	if (!(proc_file->f_mode & FMODE_LSEEK))
		rtcfs_file->f_mode &= ~FMODE_LSEEK;
	return 0;
}

/**
 * Close procfs file opened with rtcfs_proc_open().
 */
int rtcfs_proc_release(struct inode *inode, struct file *rtcfs_file)
{
	struct file *proc_file = (struct file *)rtcfs_file->private_data;

	if (proc_file)
		filp_close(proc_file, NULL); /* This calls procfs release() */

	return 0;
}

RTCFS_WRAPPER_DEFINE5(_FILE, get_unmapped_area, unsigned long,
			struct file *,	file,
			unsigned long,	orig_addr,
			unsigned long,	len,
			unsigned long,	pgoff,
			unsigned long,	flags);
static RTCFS_WRAPPER_DEFINE5(_FILE, splice_write, ssize_t,
				struct pipe_inode_info *,	pipe,
				struct file *,			file,
				loff_t *,			ppos,
				size_t,				len,
				unsigned int,			flags);
static RTCFS_WRAPPER_DEFINE5(_FILE, splice_read, ssize_t,
				struct file *,			file,
				loff_t *,			ppos,
				struct pipe_inode_info *,	pipe,
				size_t,				len,
				unsigned int,			flags);

/**
 * Set wrapper only if proc_inode has corresponding non-zero pointer.
 */
#define RTCFS_SET_OP(__op, __name, __proc_op)		\
do {							\
	if (__proc_op->__name)				\
		__op->__name = rtcfs_proc_##__name;	\
} while (0)

struct inode_operations *rtcfs_install_op_wrappers(struct inode *inode,
						const struct inode_operations *proc_op)
{
	struct inode_operations *op = NULL;

	if (proc_op) {
		op = &RTCFS_I(inode)->op;
		memset(op, 0, sizeof(struct inode_operations));

		RTCFS_SET_OP(op, lookup,	proc_op);
		RTCFS_SET_OP(op, get_link,	proc_op);
		RTCFS_SET_OP(op, permission,	proc_op);
		RTCFS_SET_OP(op, readlink,	proc_op);
		RTCFS_SET_OP(op, getattr,	proc_op);
		RTCFS_SET_OP(op, setattr,	proc_op);
	}

	return op;
}

struct file_operations *rtcfs_install_fop_wrappers(struct inode *inode,
					const struct file_operations *proc_fop)

{
	struct file_operations *fop = NULL;

	if (proc_fop) {
		fop = &RTCFS_I(inode)->fop;
		memset(fop, 0, sizeof(struct file_operations));

		RTCFS_SET_OP(fop, llseek,		proc_fop);
		RTCFS_SET_OP(fop, read,			proc_fop);
		RTCFS_SET_OP(fop, write,		proc_fop);
		RTCFS_SET_OP(fop, read_iter,	        proc_fop);
		RTCFS_SET_OP(fop, write_iter,		proc_fop);
		RTCFS_SET_OP(fop, iopoll,		proc_fop);
		RTCFS_SET_OP(fop, iterate_shared,	proc_fop);
		RTCFS_SET_OP(fop, poll,			proc_fop);
		RTCFS_SET_OP(fop, unlocked_ioctl,	proc_fop);
		RTCFS_SET_OP(fop, compat_ioctl,		proc_fop);
		RTCFS_SET_OP(fop, mmap,			proc_fop);
		RTCFS_SET_OP(fop, get_unmapped_area,	proc_fop);
		RTCFS_SET_OP(fop, splice_write,		proc_fop);
		RTCFS_SET_OP(fop, splice_read,		proc_fop);

		/**
		 * Inodes can have default (nulled) open function, but in
		 * order to have a pointer to the original proc file, we need
		 * to call our open(). It is possible that release() method
		 * is set to null too, so we always install our auxiliary
		 * functions here: one for getting the original file,
		 * and one for releasing it.
		 */
		fop->open	= rtcfs_proc_open;
		fop->release	= rtcfs_proc_release;
	}

	return fop;
}

