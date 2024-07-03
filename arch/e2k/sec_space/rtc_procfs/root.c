/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/fs_context.h>

#include "internal.h"


#define RTCFS_MAGIC 0x000e2000


static struct kmem_cache *rtcfs_inode_cachep __ro_after_init;

static void init_once(void *foo)
{
	struct rtcfs_inode *i;

	i = (struct rtcfs_inode *)foo;
	inode_init_once(&i->vfs_inode);
}

static int __init rtcfs_init_kmemcache(void)
{
	rtcfs_inode_cachep = kmem_cache_create("rtcfs_inode_cache",
					sizeof(struct rtcfs_inode), 0,
					(SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD |
					SLAB_ACCOUNT | SLAB_PANIC), init_once);
	if (!rtcfs_inode_cachep)
		return -ENOMEM;
	return 0;
}

static void rtcfs_clean_kmemcache(void)
{
	kmem_cache_destroy(rtcfs_inode_cachep);
}

static const struct inode_operations rtcfs_root_inode_operations = {
	.lookup     = rtcfs_root_lookup,
	.getattr    = rtcfs_getattr,
};

static const struct file_operations rtcfs_root_operations = {
	.read               = generic_read_dir,
	.iterate_shared     = rtcfs_readdir,
	.llseek             = generic_file_llseek,
};


static struct inode *rtcfs_alloc_inode(struct super_block *sb)
{
	struct rtcfs_inode *i;

	i = kmem_cache_alloc(rtcfs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;
	i->dentry = NULL;
	return &i->vfs_inode;
}

static void rtcfs_destroy_inode(struct inode *inode)
{
	struct dentry *dentry = RTCFS_I(inode)->dentry;

	if (dentry)
		dput(dentry);
}

static void rtcfs_free_inode(struct inode *inode)
{
	kmem_cache_free(rtcfs_inode_cachep, RTCFS_I(inode));
}

enum rtcfs_options {
	Opt_gid     = (1<<0),
	Opt_hidepid = (1<<1),
	Opt_subset  = (1<<2),
};

static void rtcfs_set_opt_flag(struct rtcfs_sb_info *sbi,
				enum rtcfs_options flag, int value)
{
	if (!value)	{
		sbi->options.mask &= ~flag;
		return;
	}

	sbi->options.mask |= flag;
	switch (flag) {
	case Opt_gid:
		sbi->options.gid = value;
		break;
	case Opt_hidepid:
		sbi->options.hidepid = value;
		break;
	case Opt_subset:
		sbi->options.subset = value;
		break;
	}
}

static int rtcfs_apply_options(struct rtcfs_sb_info *sbi, char *options)
{
	char *str_end, *cur, *val_str;
	char *p = options;
	struct pid_namespace *ns;
	int res, val;

	if (!options || !*options)
		return 0;

	str_end = options + strlen(options);
	ns = sbi->ns;

	do {
		cur = strchr(p, ',');
		if (cur)
			*cur = 0;
		else
			cur = str_end;

		val_str = strchr(p, '=');
		if (!val_str)
			return -EINVAL;
		val_str += 1;
		if (!strncmp(p, "hidepid=", 8)) {
			res = vfs_parse_fs_string(sbi->proc_fc,
				"hidepid", val_str, strlen(val_str));
			if (res)
				return res;

			res = kstrtoint(val_str, 0, &val);
			if (res)
				return -EINVAL;
			rtcfs_set_opt_flag(sbi, Opt_hidepid, val);
		} else if (!strncmp(p, "gid=", 4)) {
			res = vfs_parse_fs_string(sbi->proc_fc,
				"gid", val_str,	strlen(val_str));
			if (res)
				return res;

			res = kstrtoint(val_str, 0, &val);
			if (res)
				return -EINVAL;
			rtcfs_set_opt_flag(sbi, Opt_gid, val);
		} else if (!strncmp(p, "subset=", 7)) {
			res = vfs_parse_fs_string(sbi->proc_fc,
				"subset", val_str, strlen(val_str));
			if (res)
				return res;

			res = kstrtoint(val_str, 0, &val);
			if (res)
				return -EINVAL;
			rtcfs_set_opt_flag(sbi, Opt_subset, val);
		} else {
			return -EINVAL;
		}
		p = cur + 1;
	} while (p < str_end);
	return 0;
}

static int rtcfs_remount(struct super_block *sb, int *mount_flags, char *arg)
{
	sync_filesystem(sb);
	return rtcfs_apply_options(RTCFS_SBI(sb), arg);
}

static int rtcfs_show_options(struct seq_file *seq, struct dentry *root)
{
	char val_str[32];
	struct rtcfs_sb_info *sbi;
	struct pid_namespace *ns;

	sbi = RTCFS_SBI(root->d_sb);
	ns = sbi->ns;

	if (sbi->options.mask & Opt_gid) {
		snprintf(val_str, sizeof(val_str), "%d", sbi->options.gid);
		seq_show_option(seq, "gid", val_str);
	}
	if (sbi->options.mask & Opt_hidepid) {
		snprintf(val_str, sizeof(val_str), "%d", sbi->options.hidepid);
		seq_show_option(seq, "hidepid", val_str);
	}
	if (sbi->options.mask & Opt_subset) {
		snprintf(val_str, sizeof(val_str), "%d", sbi->options.subset);
		seq_show_option(seq, "subset", val_str);
	}
	return 0;
}

const struct super_operations rtcfs_sops = {
	.alloc_inode   = rtcfs_alloc_inode,
	.destroy_inode = rtcfs_destroy_inode,
	.free_inode    = rtcfs_free_inode,
	.remount_fs    = rtcfs_remount,
	.show_options  = rtcfs_show_options,
	.drop_inode    = generic_delete_inode,
	.statfs        = simple_statfs,
};

/* On error cleanup will be performed in rtcfs_kill_sb() */
static int rtcfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root;
	struct dentry *root_dentry;
	struct vfsmount *mnt;
	struct path path;
	struct rtcfs_sb_info *sbi;
	struct file_system_type *proc_fs_type;
	struct fs_context *proc_fc;
	int ret = 0;

	/* Looking at proc_fill_super() */
	sb->s_iflags |= SB_I_USERNS_VISIBLE | SB_I_NOEXEC | SB_I_NODEV;
	sb->s_flags |= SB_NODIRATIME | SB_NOSUID | SB_NOEXEC;
	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = RTCFS_MAGIC;
	sb->s_op = &rtcfs_sops;
	sb->s_time_gran = 1;

	sbi = kzalloc(sizeof(struct rtcfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	/* saving pointer to pid ns */
	sbi->ns = get_pid_ns(task_active_pid_ns(current));
	sbi->options.mask = 0;
	sb->s_fs_info = sbi;

	/**
	 * Mounting real proc fs. For linux < 5.*, we have to
	 * switch to old API (fs_context wasn't supported)
	 */
	proc_fs_type = get_fs_type("proc");
	if (!proc_fs_type)
		return -ENODEV;
	proc_fc = fs_context_for_mount(proc_fs_type, SB_KERNMOUNT);
	if (IS_ERR(proc_fc))
		return PTR_ERR(proc_fc);

	sbi->proc_fc = proc_fc;
	mnt = fc_mount(proc_fc);
	module_put(proc_fs_type->owner);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);
	ret = rtcfs_apply_options(sbi, data);
	if (ret)
		return ret;

	sbi->proc_mnt = mnt;

	/* getting proc root path */
	ret = vfs_path_lookup(mnt->mnt_root, mnt, "/", 0, &path);
	if (ret)
		return ret;
	root = rtcfs_duplicate_proc_inode(sb, &path);
	if (!root)
		return -ENOMEM;

	root->i_fop = &rtcfs_root_operations;
	root->i_op  = &rtcfs_root_inode_operations;
	set_nlink(root, 2);
	root_dentry = d_make_root(root);
	if (!root_dentry) {
		iput(root);
		return -EINVAL;
	}

	sb->s_root = root_dentry;
	return 0;
}

static struct dentry *rtcfs_get_super(struct file_system_type *fst, int flags,
					const char *devname, void *data)
{
	return mount_nodev(fst, flags, data, rtcfs_fill_super);
}

static void rtcfs_kill_sb(struct super_block *sb)
{
	struct rtcfs_sb_info *sbi = RTCFS_SBI(sb);

	kill_anon_super(sb);
	if (!sbi)
		return;
	if (sbi->ns)
		put_pid_ns(sbi->ns);
	if (sbi->proc_mnt)
		kern_unmount(sbi->proc_mnt);
	if (sbi->proc_fc)
		put_fs_context(sbi->proc_fc);
	kfree(sbi);
}

/* TODO: switch to the new fs_context api */
struct file_system_type rtcfs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "rtc_proc", /* name is used by __rtcfs_show_mounts */
	.mount    = rtcfs_get_super,
	.kill_sb  = rtcfs_kill_sb,
	.fs_flags = FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
};

static int __init rtcfs_init(void)
{
	int ret;

	ret = init_rtc_binfmt();
	if (ret)
		return ret;

	ret = rtcfs_init_kmemcache();
	if (ret)
		return ret;

	ret = register_filesystem(&rtcfs_fs_type);
	if (ret)
		rtcfs_clean_kmemcache();

	return ret;
}

static void __exit rtcfs_cleanup(void)
{
	unregister_filesystem(&rtcfs_fs_type);
	rcu_barrier();
	rtcfs_clean_kmemcache();
	exit_rtc_binfmt();
}

module_init(rtcfs_init);
module_exit(rtcfs_cleanup);

MODULE_ALIAS_FS("rtc_proc");
MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("extended support for binary compiler");
MODULE_VERSION("0.2");

