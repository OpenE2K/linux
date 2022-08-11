// SPDX-License-Identifier: GPL-2.0
/*
 * Kiosk Linux Security Module
 *
 * Author: Oleg Solovyov <mcpain@altlinux.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/tty.h>

#include <net/genetlink.h>

#define MAX_PATH 1024

struct kiosk_list_struct {
	struct path path;
	struct list_head list;
};

static struct kiosk_list_struct *list_iter;
static struct genl_family genl_kiosk_family;
static char pathbuf[MAX_PATH];

/* Lists handling */
static DECLARE_RWSEM(user_sem);
static LIST_HEAD(user_list);

enum kiosk_cmd {
	KIOSK_UNSPEC = 0,
	KIOSK_REQUEST,
	KIOSK_REPLY,
	KIOSK_CMD_LAST,
};

enum kiosk_mode {
	KIOSK_PERMISSIVE = 0,
	KIOSK_NONSYSTEM,
	KIOSK_MODE_LAST,
};

static int kiosk_mode = KIOSK_PERMISSIVE;

enum kiosk_action {
	KIOSK_SET_MODE = 0,
	KIOSK_USERLIST_ADD,
	KIOSK_USERLIST_DEL,
	KIOSK_USER_LIST,
};

enum kiosk_attrs {
	KIOSK_NOATTR = 0,
	KIOSK_ACTION,
	KIOSK_DATA,
	KIOSK_MAX_ATTR,
};

static struct nla_policy kiosk_policy[KIOSK_MAX_ATTR] = {
	[KIOSK_ACTION] = {
		.type = NLA_S16,
	},
	[KIOSK_DATA] = {
		.type = NLA_STRING,
		.len = sizeof(pathbuf) - 1
	},
};

static int kiosk_add_item(struct list_head *list, char *filename,
		struct rw_semaphore *sem)
{
	struct kiosk_list_struct *item, *tmp;
	int mode;
	int rc;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	rc = kern_path(filename, LOOKUP_FOLLOW, &item->path);
	if (rc) {
		pr_err("Kiosk: error lookup '%s'\n", filename);
		kfree(item);
		return rc;
	}

	mode = d_inode(item->path.dentry)->i_mode;
	if (!S_ISREG(mode)) {
		pr_err("Kiosk: given file is not a regular file, mode: %d\n",
		       mode);
		path_put(&item->path);
		kfree(item);
		return -EINVAL;
	}

	down_write(sem);
	list_for_each_entry(tmp, list, list) {
		if (item->path.dentry == tmp->path.dentry) {
			up_write(sem);
			path_put(&item->path);
			kfree(item);
			return 0;
		}
	}
	list_add_tail(&item->list, list);
	up_write(sem);

	return 0;
}

static int kiosk_remove_item(struct list_head *list, char *filename,
			     struct rw_semaphore *sem)
{
	struct kiosk_list_struct *item, *tmp;
	struct path user_path;
	int rc;

	rc = kern_path(filename, LOOKUP_FOLLOW, &user_path);
	if (rc)
		return rc;

	down_write(sem);
	list_for_each_entry_safe(item, tmp, list, list) {
		if (item->path.dentry == user_path.dentry) {
			if (item == list_iter) {
				pr_err("Kiosk: list is being iterated, item removing is unsafe\n");
				up_write(sem);
				path_put(&user_path);
				return -EAGAIN;
			}
			list_del(&item->list);
			path_put(&item->path);
			kfree(item);
		}
	}
	up_write(sem);
	path_put(&user_path);
	return 0;
}

static int kiosk_nl_send_msg(struct sk_buff *skb, struct genl_info *info,
			     char *msg)
{
	int msg_size;
	int res;
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;

	msg_size = strlen(msg) + 1;
	/* we put string so add space for NUL-terminator */

	skb_out = genlmsg_new(msg_size, GFP_KERNEL);
	if (!skb_out)
		return -ENOMEM;

	nlh = genlmsg_put_reply(skb_out, info, &genl_kiosk_family, 0,
				KIOSK_REPLY);
	if (!nlh) {
		nlmsg_free(skb_out);
		return -ENOMEM;
	}

	res = nla_put_string(skb_out, KIOSK_DATA, msg);
	if (res) {
		nlmsg_free(skb_out);
		return res;
	}

	genlmsg_end(skb_out, nlh);
	return genlmsg_reply(skb_out, info);
}

static int kiosk_list_items(struct list_head *list, struct rw_semaphore *sem,
			    struct sk_buff *skb, struct genl_info *info)
{
	char *path;

	down_read(sem);

	if (!list_iter) { /* list iterating started */
		list_iter = list_first_entry_or_null(list,
						     struct kiosk_list_struct,
						     list);
	} else if (list_iter == list_last_entry(list,
						struct kiosk_list_struct,
						list)) {
		/* hit list end, cleaning temp variable */
		list_iter = NULL;
	} else { /* iterating list */
		list_iter = list_next_entry(list_iter, list);
	}

	if (list_iter)
		path = d_path(&list_iter->path, pathbuf, sizeof(pathbuf));
	else
		path = "";

	up_read(sem);
	return kiosk_nl_send_msg(skb, info, path);
}

static int kiosk_genl_doit(struct sk_buff *skb, struct genl_info *info)
{
	int action;

	if (info->attrs[KIOSK_DATA])
		strlcpy(pathbuf, nla_data(info->attrs[KIOSK_DATA]), sizeof(pathbuf));
	else
		pathbuf[0] = '\0';

	action = info->attrs[KIOSK_ACTION] ?
		nla_get_s16(info->attrs[KIOSK_ACTION]) : -1;

	switch (action) {
	case KIOSK_SET_MODE: {
		int new_mode;
		int error;
		char buf[4];

		if (!strlen(pathbuf)) {
			/* we want to retrieve current mode */
			snprintf(buf, sizeof(buf), "%d", kiosk_mode);
			return kiosk_nl_send_msg(skb, info, buf);
		}

		error = kstrtouint(pathbuf, 0, &new_mode);

		if (error || new_mode < 0
			  || new_mode >= KIOSK_MODE_LAST) {
			return -EINVAL;
		}
		kiosk_mode = new_mode;
		return 0;
	}
	case KIOSK_USERLIST_ADD:
		return kiosk_add_item(&user_list, pathbuf, &user_sem);
	case KIOSK_USERLIST_DEL:
		return kiosk_remove_item(&user_list, pathbuf,
					 &user_sem);
	case KIOSK_USER_LIST:
		return kiosk_list_items(&user_list, &user_sem, skb,
					info);
	default:
		return -EINVAL;
	}
}

static const struct genl_ops genl_kiosk_ops[] = {
	{
		.doit = kiosk_genl_doit,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family genl_kiosk_family = {
	.name = "kiosk",
	.version = 1,
	.netnsok = false,
	.module = THIS_MODULE,
	.ops = genl_kiosk_ops,
	.n_ops = ARRAY_SIZE(genl_kiosk_ops),
	.maxattr = KIOSK_MAX_ATTR,
	.policy = kiosk_policy,
};

/* Hooks */
static int kiosk_bprm_set_creds(struct linux_binprm *bprm)
{
	uid_t cur_uid = __kuid_val(bprm->cred->uid);
	struct kiosk_list_struct *node;

	if (kiosk_mode == KIOSK_PERMISSIVE)
		return 0;

	if (cur_uid >= 500) {
		bprm->secureexec = 1;
		if (bprm->called_set_creds)
			return 0;

		if (cur_uid == __kuid_val(bprm->file->f_inode->i_uid) ||
		    (bprm->file->f_inode->i_mode & 0022)) {
			pr_notice_ratelimited("Kiosk: %s is writable for %d\n",
					      bprm->filename, cur_uid);
			return -EPERM;
		}

		down_read(&user_sem);
		list_for_each_entry(node, &user_list, list) {
			if (bprm->file->f_path.dentry == node->path.dentry) {
				up_read(&user_sem);
				return 0;
			}
		}
		up_read(&user_sem);
	} else {
		return 0;
	}

	pr_notice_ratelimited("Kiosk: %s prevented to exec from %d\n",
			      bprm->filename, cur_uid);
	return -EPERM;
}

static struct security_hook_list kiosk_hooks[] = {
	LSM_HOOK_INIT(bprm_set_creds, kiosk_bprm_set_creds),
};

static int __init kiosk_init(void)
{
	int rc;

	rc = genl_register_family(&genl_kiosk_family);

	if (rc) {
		pr_alert("Kiosk: Error registering family.\n");
		return rc;
	}

	pr_info("Kiosk: Netlink family registered.\n");
	security_add_hooks(kiosk_hooks, ARRAY_SIZE(kiosk_hooks), "kiosk");

	return 0;
}

DEFINE_LSM(kiosk) = {
	.name = "kiosk",
	.init = kiosk_init,
};
