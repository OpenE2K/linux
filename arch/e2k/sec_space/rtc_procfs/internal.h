/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/binfmts.h>

struct rtcfs_sb_info {
	struct pid_namespace *ns;
	struct vfsmount *proc_mnt;
	struct fs_context *proc_fc;
	struct options {
		unsigned int mask;
		int hidepid;
		int gid;
		int subset;
	} options;
};

extern struct file_system_type rtcfs_fs_type;

/* Entry of rtc_proc cache */
struct rtcfs_inode {
	struct dentry		*dentry;	// pointer to corresponding procfs dentry
	struct file_operations	fop;		// procfs i_fop wrappers
	struct inode_operations op;		// procfs i_op wrappers
	struct inode		vfs_inode;	// rtc_proc inode
};

struct rtcfs_dir_context {
	struct file		*file;
	struct dir_context	*proc_ctx;
	struct dir_context	ctx;
};

static inline struct rtcfs_inode *RTCFS_I(const struct inode *inode)
{
	return container_of(inode, struct rtcfs_inode, vfs_inode);
}

static inline struct dentry *PROC_DENTRY(const struct inode *inode)
{
	return RTCFS_I(inode)->dentry;
}

static inline struct inode *PROC_INODE(const struct inode *inode)
{
	return d_inode(PROC_DENTRY(inode));
}

static inline struct rtcfs_sb_info *RTCFS_SBI(struct super_block *sb)
{
	return (struct rtcfs_sb_info *)sb->s_fs_info;
}

static inline struct pid_namespace *RTCFS_NS(struct super_block *sb)
{
	return RTCFS_SBI(sb)->ns;
}

static inline struct inode *file_to_procfile(struct file *proc_file, struct file *file)
{
	struct inode *proc_inode;
	struct inode *inode;

	memset(proc_file, 0, sizeof(struct file));

	atomic_long_set(&proc_file->f_count, 1);
	rwlock_init(&proc_file->f_owner.lock);
	spin_lock_init(&proc_file->f_lock);
	mutex_init(&proc_file->f_pos_lock);

	spin_lock(&file->f_lock);
	proc_file->f_flags	= file->f_flags;
	proc_file->f_mode	= file->f_mode;
	proc_file->f_version	= file->f_version;
	proc_file->private_data	= file->private_data;
	proc_file->f_pos	= file->f_pos;
	proc_file->f_cred	= file->f_cred;
	spin_unlock(&file->f_lock);

	inode		= file_inode(file);
	proc_inode	= PROC_INODE(inode);

	proc_file->f_inode		= proc_inode;
	proc_file->f_path.dentry	= PROC_DENTRY(inode);
	proc_file->f_path.mnt		= RTCFS_SBI(inode->i_sb)->proc_mnt;
	proc_file->f_op			= proc_inode->i_fop;

	return proc_inode;
}

static inline void procfile_to_file(struct file *file, struct file *proc_file)
{
	spin_lock(&file->f_lock);
	file->f_version		= proc_file->f_version;
	file->f_pos		= proc_file->f_pos;
	file->private_data	= proc_file->private_data;
	spin_unlock(&file->f_lock);
}

extern struct task_struct *rtcfs_get_proc_task(const char *name,
						struct pid_namespace *ns);

extern int rtcfs_pid_readdir(struct file *file, struct dir_context *ctx);
extern struct inode *rtcfs_duplicate_proc_inode(struct super_block *sb,
						const struct path *path,
						const struct file_operations *fop,
						const struct inode_operations *op);
extern struct dentry *rtcfs_root_lookup(struct inode *dir, struct dentry *dentry,
							unsigned int flags);
extern int __rtcfs_dir_lookup(struct inode *dir, struct dentry *dentry,
						struct path *path);
extern struct dentry *rtcfs_allocate_object(struct dentry *dentry,
					const struct path *proc_path,
					const struct file_operations *fop,
					const struct inode_operations *op);

struct bincomp_map_info {
	u64 rip;
	u64 rsp;
	u64 brk;
	u64 at_base;
	u64 at_entry;
	u64 at_phnum;
	u64 at_phent;
	u64 at_phdr;
	u64 vdso;
};

extern int rtc_load_x86_elf32(struct linux_binprm *bprm,
				struct bincomp_map_info *map_info,
				bool is_support_em64t, bool is_topdown);
extern int rtc_load_x86_elf64(struct linux_binprm *bprm,
				struct bincomp_map_info *map_info,
				bool is_support_em64t, bool is_topdown);
extern int rtc_load_bincomp_elf32(struct linux_binprm *bprm,
				struct bincomp_map_info *map_info);
extern int rtc_load_bincomp_elf64(struct linux_binprm *bprm,
				struct bincomp_map_info *map_info);

