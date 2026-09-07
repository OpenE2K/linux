/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/user_namespace.h>
#include <linux/path.h>
#include <linux/stat.h>
#include <linux/dcache.h>

/* inode_operations */
extern struct dentry *rtcfs_proc_lookup(struct inode *dir, struct dentry *dentry, unsigned int);
extern int rtcfs_proc_permission(struct user_namespace *mnt_userns,
				struct inode *inode, int mask);
extern int rtcfs_proc_getattr(struct user_namespace *mnt_userns,
				const struct path *path, struct kstat *stat,
				u32 request_mask, unsigned int query_flags);
extern int rtcfs_proc_setattr(struct user_namespace *mnt_userns,
				struct dentry *dentry, struct iattr *attr);
/* file_operations */
extern loff_t rtcfs_proc_llseek(struct file *file, loff_t off, int whence);
extern ssize_t rtcfs_proc_read(struct file *file, char __user *buf,
				size_t size, loff_t *off);
extern ssize_t rtcfs_proc_write(struct file *file, const char __user *buf,
				size_t size, loff_t *off);
extern ssize_t rtcfs_proc_read_iter(struct kiocb *iocb, struct iov_iter *iter);
__poll_t rtcfs_proc_poll(struct file *file, struct poll_table_struct *pts);
extern long rtcfs_proc_unlocked_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg);
extern int rtcfs_proc_mmap(struct file *file, struct vm_area_struct *vma);
extern unsigned long rtcfs_proc_get_unmapped_area(struct file *file,
			unsigned long orig_addr, unsigned long len,
			unsigned long pgoff, unsigned long flags);
/**
 * Warning: each rtcfs object that can call original procfs methods must have
 * properly allocated struct rtcfs_inode->file. Therefore, it's required to
 * set rtcfs_proc_open for method explicitly even if proc object itself doesn't
 * have such method.
 */
int rtcfs_proc_open(struct inode *inode, struct file *file);
int rtcfs_proc_release(struct inode *inode, struct file *file);


struct inode_operations *rtcfs_install_op_wrappers(struct inode *inode,
						const struct inode_operations *proc_op);
struct file_operations *rtcfs_install_fop_wrappers(struct inode *inode,
						const struct file_operations *proc_fop);
