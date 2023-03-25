#pragma once
#include <linux/fs.h>
#include <linux/version.h>

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

typedef void (*nd_jump_link_t)(struct path *path);
extern nd_jump_link_t nameidata_jump_link;

extern struct file_system_type rtcfs_fs_type;

struct rtcfs_inode {
	struct path  path;
	struct inode vfs_inode;
};

static inline struct rtcfs_inode *RTCFS_I(const struct inode *inode)
{
	return container_of(inode, struct rtcfs_inode, vfs_inode);
}

static inline struct path *PROC_PATH(const struct inode *inode)
{
	return &RTCFS_I(inode)->path;
}

static inline struct dentry *PROC_DENTRY(const struct inode *inode)
{
	return PROC_PATH(inode)->dentry;
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

static inline void file_to_procfile(struct file *proc_file, struct file *file)
{
	memcpy(proc_file, file, sizeof(struct file));
	proc_file->f_inode = PROC_INODE(file_inode(file));
	proc_file->f_path  = *PROC_PATH(file_inode(file));
}

struct task_struct *rtcfs_get_proc_task(struct dentry *dentry,
						struct pid_namespace *ns);

int rtcfs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
						unsigned int query_flags);
int rtcfs_readdir(struct file *file, struct dir_context *ctx);
struct inode *rtcfs_duplicate_proc_inode(struct super_block *sb,
						const struct path *path);
struct dentry *rtcfs_root_lookup(struct inode *dir, struct dentry *dentry,
							unsigned int flags);
int rtcfs_init_op(void);
