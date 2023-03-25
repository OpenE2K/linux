/*
 *  dmp_assist.c - MCST dump-analyzer assistant Driver 
 *  Copyright (C) 2011 Mikhail Kharitonov <mikharit@mcst.ru>
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mm.h>

#include <asm/string.h>

#include "dmp_assist.h"

/* enable debug output? */
#define DMP_DEBUG 0

#if DMP_DEBUG
#define DPRINT(fmt, args...)	printk(fmt, ##args);
#else
#define DPRINT(fmt, args...)
#endif

static char *dev_name = "dmp_assist";
static int Major;
#if 0
static int Minor;
static dev_t dev;
#endif

static int dmp_open (struct inode *inode, struct file *file);
static int dmp_close(struct inode *inode, struct file *file);
static long dmp_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int dmp_mmap(struct file *file, struct vm_area_struct * vma);
static long dmp_unlink(const char * pathname);

static struct file_operations dmp_fops = {
	.owner   = THIS_MODULE,
	.open    = dmp_open,  /* open  */
	.release = dmp_close, /* close */
	.unlocked_ioctl   = dmp_ioctl, /* ioctl */
	.mmap    = dmp_mmap,  /* mmap  */
};

static int dmp_open (struct inode *inode, struct file *file)
{
	DPRINT("dmp_assist driver open().\n");
	return 0;
}

static int dmp_close (struct inode *inode, struct file *file)
{
	DPRINT("dmp_assist driver close().\n");
	return 0;
}

#ifdef CONFIG_RECOVERY
extern e2k_addr_t cntp_kernel_base;
#endif
static long dmp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	DPRINT("dmp_ioctl() cmd:0x%x.\n", cmd);
	switch (cmd) {
	case IOCTL_DMP_ASSIST_kernel_base:
		DPRINT("dmp_ioctl() IOCTL_DMP_ASSIST_kernel_base cmd*\n", cmd);
#ifdef CONFIG_RECOVERY
		return cntp_kernel_base;
#else
		printk(KERN_ERR "dmp_ioctl() Err: No CONFIG_RECOVERY\n");
		return -EINVAL;
#endif
	default:
		printk(KERN_INFO "dmp_ioctl(): unknown ioctl command:0x%lx,"
			"IOCTL_DMP_ASSIST_kernel_base:0x%lx\n",
				cmd, IOCTL_DMP_ASSIST_kernel_base);
		return -EINVAL;
	}
	return 0;
}

static int dmp_mmap(struct file * file, struct vm_area_struct * vma)
{
	size_t size = vma->vm_end - vma->vm_start;

	DPRINT("dmp_mmap() vma:%p start:0x%lx end:0x%lx"
		"  size:0x%lx pgoff:0x%lx prot:0x%lx\n",
	    	vma, vma->vm_start, vma->vm_end, size,
		vma->vm_pgoff, vma->vm_page_prot);

	/* Remap-pfn-range will mark the range VM_IO and VM_RESERVED */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}

	return 0;
}


static long dmp_mknod(const char *filename, int mode, unsigned dev)
{
	int error = 0;
	struct dentry *file_dentry;
	struct nameidata nd;

	DPRINT("---dmp_mknod(): start for %s\n", filename);
	error = path_lookup(filename, LOOKUP_PARENT, &nd);
	DPRINT("---dmp_mknod() ret path_lookup %d\n", error);
	if (error)
		goto out;
	file_dentry = lookup_create(&nd, 0); /* Returns with 
                                              * nd->path.dentry->d_inode->i_mutex
					      * locked.
					      */
	error = PTR_ERR(file_dentry);
	DPRINT("---dmp_mknod() PTR_ERR(file_dentry) 0x%lx\n", error);
	if (!IS_POSIXACL(nd.path.dentry->d_inode))
		mode &= (~current_umask());
	if (IS_ERR(file_dentry)) {
		goto out_unlock;
	}
	error = vfs_mknod(nd.path.dentry->d_inode, file_dentry,
			mode, new_decode_dev(dev));
	DPRINT("---dmp_mknod() ret vfs_mknod() %d\n", error);
	dput(file_dentry);
out_unlock:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
out:
	if (error == -EEXIST) {
		DPRINT("---dmp_mknod() error == EEXIST remove entry\n");
		dmp_unlink(dev_path);
		return (dmp_mknod(filename, mode, dev));
	}
	return error;
}

long dmp_unlink(const char * pathname)
{
	int error = 0;
	struct dentry *file_dentry;
	struct nameidata nd;
	struct inode *inode = NULL;

	DPRINT("---dmp_unlink() enter\n");

	error = path_lookup(pathname, LOOKUP_PARENT, &nd);
	DPRINT("---dmp_unlink() ret path_lookup  %d\n", error);
	if (error)
		return error;
	DPRINT("---dmp_unlink() after path_lookup parent_name:  %s\n",
			nd.path.dentry->d_name.name);
	error = -EISDIR;
	if (nd.last_type != LAST_NORM)
		return error;
	mutex_lock(&nd.path.dentry->d_inode->i_mutex);
	file_dentry = lookup_one_len(nd.last.name, nd.path.dentry,
				strlen(nd.last.name));
	error = PTR_ERR(file_dentry);
	if (!IS_ERR(file_dentry)) {
		if (nd.last.name[nd.last.len]) {
			DPRINT("---dmp_unlink() nd.last.name[nd.last.len] %d\n",
				nd.last.name[nd.last.len]);
			error = !file_dentry->d_inode ? -ENOENT :
			S_ISDIR(file_dentry->d_inode->i_mode) ?
				-EISDIR : -ENOTDIR;
		} else {
			inode = file_dentry->d_inode;
			if (inode)
				atomic_inc(&inode->i_count);
			DPRINT("---dmp_unlink() name:%s\n",
				file_dentry->d_name.name);
			error = vfs_unlink(nd.path.dentry->d_inode, file_dentry);
			DPRINT("---dmp_unlink() ret vfs_unlink %d\n", error);
		}
		dput(file_dentry);
	} else {
		printk("---dmp_unlink() ret lookup_one_len %d\n", error);
	}
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	if (inode)
		iput(inode);	/* truncate the inode here */
	path_put(&nd.path);
	return error;
}

static int __init dmp_init(void)
{
#if 0
	int rval = 0;
	mode_t mode = 0;
#endif
	Major = register_chrdev(MAJOR_NUM, dev_name, &dmp_fops);
	if (Major < 0) {
		printk("dmp_init(): Register failed %d\n", Major);
		return Major;
	}
#if 0
	Minor = 0;
	dev = (Major << 8) | Minor;
	DPRINT("dmp_init(): dev:0x%lx\n", dev);
	mode = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	rval = dmp_mknod(dev_path, (mode | S_IFCHR) , dev);
	if (rval) {
		printk("dmp_init(): dmp_mknod() failed %d\n", rval);
		return rval;
	}
#endif
	printk("dmp_assist driver installed. Major:0x%lx(%d)\n", MAJOR_NUM,
		MAJOR_NUM);
	return 0;
}

static void __exit dmp_exit(void)
{
	dmp_unlink(dev_path);
	unregister_chrdev(Major, dev_name);
	DPRINT("dmp_assist driver exited.\n");
}

module_init(dmp_init);
module_exit(dmp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mikhail Kharitonov <mikharit@mcst.ru>");
MODULE_DESCRIPTION("Dump-analyzer assistant Driver");
