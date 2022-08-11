/*
 * AltHa Linux Security Module
 *
 * Author: Anton Boyarshinov <boyarsh@altlinux.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/sysctl.h>
#include <linux/binfmts.h>
#include <linux/file.h>
#include <linux/ratelimit.h>
#include <linux/moduleparam.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <asm/uaccess.h>

#define ALTHA_PARAMS_SIZE 4096
char proc_nosuid_exceptions[ALTHA_PARAMS_SIZE];
char proc_interpreters[ALTHA_PARAMS_SIZE];
char proc_olock_dirs[ALTHA_PARAMS_SIZE];

/* Boot time disable flag */
static bool altha_enabled = 0;

/* sysctl flags */
static int nosuid_enabled;
static int rstrscript_enabled;
static int olock_enabled;

/* Boot parameter handing */
module_param_named(enabled, altha_enabled, bool, S_IRUGO);

static int __init altha_enabled_setup(char *str)
{
	unsigned long enabled;
	int error = kstrtoul(str, 0, &enabled);
	if (!error)
		altha_enabled = enabled ? 1 : 0;
	return 1;
}

__setup("altha=", altha_enabled_setup);

struct altha_list_struct {
	struct path path;
	char * spath;
	char * spath_p;
	struct list_head list;
};

/* Lists handling */
DECLARE_RWSEM(nosuid_exceptions_sem);
DECLARE_RWSEM(interpreters_sem);
DECLARE_RWSEM(olock_dirs_sem);
LIST_HEAD(nosuid_exceptions_list);
LIST_HEAD(interpreters_list);
LIST_HEAD(olock_dirs_list);

static int altha_list_handler(struct ctl_table *table, int write,
			      void __user * buffer, size_t * lenp,
			      loff_t * ppos)
{
	struct altha_list_struct *item, *tmp;
	struct list_head *list_struct;
	char *p, *fluid;
	char *copy_buffer;
	struct rw_semaphore *sem = table->extra2;
	unsigned long error = proc_dostring(table, write, buffer, lenp, ppos);
	down_write(sem);
	if (error)
		goto out;

	if (write && !error) {
		copy_buffer = kmalloc(ALTHA_PARAMS_SIZE, GFP_KERNEL);
		if (!copy_buffer) {
			pr_err
			    ("AltHa: can't get memory for copy_buffer processing sysctl\n");
			error = -1;
			goto out;
		}

		list_struct = (struct list_head *)(table->extra1);
		/*empty list and that fill with new info */
		list_for_each_entry_safe(item, tmp, list_struct, list) {
			list_del(&item->list);
			path_put(&item->path);
			kfree(item->spath_p);
			kfree(item);
		}

		strlcpy(copy_buffer, table->data, ALTHA_PARAMS_SIZE);

		/* buffer can have a garbage after \n */
		p = strchrnul(copy_buffer, '\n');
		*p = 0;

		/* for strsep usage */
		fluid = copy_buffer;

		while ((p = strsep(&fluid, ":\n")) != NULL) {
			if (strlen(p)) {
				item = kmalloc(sizeof(*item), GFP_KERNEL);
				if (item)
					item->spath_p = kmalloc(PATH_MAX, GFP_KERNEL);
				if (!item || !item->spath_p) {
					pr_err
					    ("AltHa: can't get memory processing sysctl\n");
					kfree(copy_buffer);
					error = -1;
					goto out;
				}
				if (kern_path(p, LOOKUP_FOLLOW, &item->path)) {
					pr_info
					    ("AltHa: error lookup '%s'\n", p);
					kfree(item);
				} else {
					item->spath=d_path(&item->path,item->spath_p,PATH_MAX);
					list_add_tail(&item->list, list_struct);
				}
			}
		}
		kfree(copy_buffer);
	}
out:
	up_write(sem);
	return error;
}

struct ctl_path nosuid_sysctl_path[] = {
	{.procname = "kernel",},
	{.procname = "altha",},
	{.procname = "nosuid",},
	{}
};

static struct ctl_table nosuid_sysctl_table[] = {
	{
	 .procname = "enabled",
	 .data = &nosuid_enabled,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = proc_dointvec_minmax,
	 },
	{
	 .procname = "exceptions",
	 .data = proc_nosuid_exceptions,
	 .maxlen = ALTHA_PARAMS_SIZE,
	 .mode = 0644,
	 .proc_handler = altha_list_handler,
	 .extra1 = &nosuid_exceptions_list,
	 .extra2 = &nosuid_exceptions_sem,
	 },
	{}
};

struct ctl_path rstrscript_sysctl_path[] = {
	{.procname = "kernel",},
	{.procname = "altha",},
	{.procname = "rstrscript",},
	{}
};

static struct ctl_table rstrscript_sysctl_table[] = {
	{
	 .procname = "enabled",
	 .data = &rstrscript_enabled,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 },
	{
	 .procname = "interpreters",
	 .data = proc_interpreters,
	 .maxlen = ALTHA_PARAMS_SIZE,
	 .mode = 0644,
	 .proc_handler = altha_list_handler,
	 .extra1 = &interpreters_list,
	 .extra2 = &interpreters_sem,
	 },
	{}
};

struct ctl_path olock_sysctl_path[] = {
	{.procname = "kernel",},
	{.procname = "altha",},
	{.procname = "olock",},
	{}
};

static struct ctl_table olock_sysctl_table[] = {
	{
	 .procname = "enabled",
	 .data = &olock_enabled,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 },
	{
	 .procname = "dirs",
	 .data = proc_olock_dirs,
	 .maxlen = ALTHA_PARAMS_SIZE,
	 .mode = 0644,
	 .proc_handler = altha_list_handler,
	 .extra1 = &olock_dirs_list,
	 .extra2 = &olock_dirs_sem,
	 },
	{}
};

struct altha_readdir_callback {
	struct dir_context ctx;
	u64 inode;
	int found;
};

int is_olock_dir(struct inode *inode)
{
	struct altha_list_struct *node;
	down_read(&olock_dirs_sem);
	list_for_each_entry(node, &olock_dirs_list, list) {
		struct inode *exc_inode = node->path.dentry->d_inode;
		if (exc_inode == inode) {
			up_read(&olock_dirs_sem);
			return 1;
		}
	}
	up_read(&olock_dirs_sem);
	return 0;
}

/* Hooks */
static int altha_bprm_set_creds(struct linux_binprm *bprm)
{
	struct altha_list_struct *node;
	/* when it's not a shebang issued script interpreter */
	if (rstrscript_enabled && !bprm->called_set_creds) {
		char path_buffer[PATH_MAX];
		char *path_p;
		path_p = d_path(&bprm->file->f_path,path_buffer,PATH_MAX);
		down_read(&interpreters_sem);
		list_for_each_entry(node, &interpreters_list, list) {
			if (strcmp(path_p, node->spath) == 0) {
				uid_t cur_uid = from_kuid(bprm->cred->user_ns,
							  bprm->cred->uid);
				pr_notice_ratelimited
				    ("AltHa/RestrScript: %s is blocked to run directly by %d\n",
				     bprm->filename, cur_uid);
				up_read(&interpreters_sem);
				return -EPERM;
			}
		}
		up_read(&interpreters_sem);
	}
	if (unlikely(nosuid_enabled &&
		     !uid_eq(bprm->cred->uid, bprm->cred->euid))) {
		char path_buffer[PATH_MAX];
		char *path_p;
		uid_t cur_uid = from_kuid(bprm->cred->user_ns, bprm->cred->uid);
		path_p = d_path(&bprm->file->f_path,path_buffer,PATH_MAX);
		down_read(&nosuid_exceptions_sem);
		list_for_each_entry(node, &nosuid_exceptions_list, list) {
			if (strcmp(path_p, node->spath) == 0) {
				pr_notice_ratelimited
				    ("AltHa/NoSUID: %s permitted to setuid from %d\n",
				     bprm->filename, cur_uid);
				up_read(&nosuid_exceptions_sem);
				return 0;
			}
		}
		up_read(&nosuid_exceptions_sem);
		pr_notice_ratelimited
		    ("AltHa/NoSUID: %s prevented to setuid from %d\n",
		     bprm->filename, cur_uid);
		bprm->cred->euid = bprm->cred->uid;
	}
	return 0;
}

/* For OLock */
static int altha_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	if (olock_enabled && (atomic_read(&dentry->d_inode->i_writecount)
#ifdef CONFIG_IMA
			|| atomic_read(&dentry->d_inode->i_readcount)
#endif
			)) {
		if (is_olock_dir(inode))
			return -EPERM;
	}
	return 0;
}

/* Initialization */

static struct security_hook_list altha_hooks[] = {
	LSM_HOOK_INIT(bprm_set_creds, altha_bprm_set_creds),
	LSM_HOOK_INIT(inode_unlink, altha_inode_unlink),
};

static int __init altha_init(void)
{
	if (altha_enabled) {
		pr_info("AltHa enabled.\n");
		security_add_hooks(altha_hooks, ARRAY_SIZE(altha_hooks),"altha");

		if (!register_sysctl_paths
		    (nosuid_sysctl_path, nosuid_sysctl_table))
			panic("AltHa: NoSUID sysctl registration failed.\n");

		if (!register_sysctl_paths
		    (rstrscript_sysctl_path, rstrscript_sysctl_table))
			panic
			    ("AltHa: RestrScript sysctl registration failed.\n");

		if (!register_sysctl_paths
		    (olock_sysctl_path, olock_sysctl_table))
			panic("AltHa: OLock sysctl registration failed.\n");
	} else
		pr_info("AltHa disabled.\n");
	return 0;
}

DEFINE_LSM(altha) = {
       .name = "altha",
       .init = altha_init,
};

