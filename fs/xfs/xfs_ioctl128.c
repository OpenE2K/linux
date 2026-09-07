/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/mount.h>
#include <linux/fsmap.h>
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_iwalk.h"
#include "xfs_itable.h"
#include "xfs_fsops.h"
#include "xfs_rtalloc.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_attr.h"
#include "xfs_ioctl.h"
#include "xfs_ioctl32.h"
#include "xfs_trace.h"
#include "xfs_sb.h"

#define  _NATIVE_IOC(cmd, type) \
	  _IOC(_IOC_DIR(cmd), _IOC_TYPE(cmd), _IOC_NR(cmd), sizeof(type))



/* XFS_IOC_FSBULKSTAT and friends */


/* copied from xfs_ioctl.c */
struct xfs_fsop_bulkreq128 {
	e2k_ap_t	lastip; /* last inode # pointer to u64  */
	__s32           icount; /* count of entries in buffer   */
	e2k_ap_t	ubuffer;/* user buffer for inode desc.  */
	e2k_ap_t	ocount; /* output count pointer to s32     */
};
#define XFS_IOC_FSBULKSTAT_128 \
	_NATIVE_IOC(XFS_IOC_FSBULKSTAT, struct xfs_fsop_bulkreq128)
#define XFS_IOC_FSBULKSTAT_SINGLE_128 \
	_NATIVE_IOC(XFS_IOC_FSBULKSTAT_SINGLE, struct xfs_fsop_bulkreq128)
#define XFS_IOC_FSINUMBERS_128 \
	_NATIVE_IOC(XFS_IOC_FSINUMBERS, struct xfs_fsop_bulkreq128)



static int xfs_ptr128_ioc_fsbulkstat(struct file		*file,
				     unsigned int		  cmd,
				     struct xfs_fsop_bulkreq128 __user *p128)
{
	struct xfs_mount	*mp = XFS_I(file_inode(file))->i_mount;
	struct xfs_fsop_bulkreq	bulkreq;
	struct xfs_ibulk	breq = {
		.mp		= mp,
		.mnt_userns	= file_mnt_user_ns(file),
		.ocount		= 0,
	};
	xfs_ino_t		lastino;
	e2k_ap_t		ap;
	int			tag;
	int			error;


	/* done = 1 if there are more stats to get and if bulkstat */
	/* should be called again (unused here, but used in dmapi) */

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (xfs_is_shutdown(mp))
		return -EIO;

	if (get_user_tagged_16(ap.qword, tag, &p128->lastip)) {
		return -EFAULT;
	}
	if (IS_AP(ap, tag)) {
		if (AP_OBJ_SIZE(ap) < sizeof(xfs_ino_t))
			return -EFAULT;
		bulkreq.lastip = (void __user *)AP_PTR(ap);
	} else if (AP_NULL(ap, tag)) {
		bulkreq.lastip = NULL;
	} else {
		return -EFAULT;
	}
	if (get_user(bulkreq.icount, &p128->icount) || bulkreq.icount <= 0)
		return -EFAULT;

	if (get_user_tagged_16(ap.qword, tag, &p128->ubuffer) || !IS_AP(ap, tag) ||
			AP_OBJ_SIZE(ap) < bulkreq.icount)
		return -EFAULT;
	bulkreq.ubuffer = (void __user *)AP_PTR;

	if (get_user_tagged_16(ap.qword, tag, &p128->ocount)) {
		return -EFAULT;
	}
	if (IS_AP(ap, tag)) {
		if (AP_OBJ_SIZE(ap) < sizeof(__s64))
			return -EFAULT;
		bulkreq.ocount = (void __user *)AP_PTR(ap);
	} else if (AP_NULL(ap, tag)) {
		bulkreq.ocount = NULL;
	} else {
		return -EFAULT;
	}
	set_u_border(MAX_U_BORDER);

	if (copy_from_user(&lastino, bulkreq.lastip, sizeof(xfs_ino_t)))
		return -EFAULT;

	breq.ubuffer = bulkreq.ubuffer;
	breq.icount = bulkreq.icount;


	/*
	 * FSBULKSTAT_SINGLE expects that *lastip contains the inode number
	 * that we want to stat.  However, FSINUMBERS and FSBULKSTAT expect
	 * that *lastip contains either zero or the number of the last inode to
	 * be examined by the previous call and return results starting with
	 * the next inode after that.  The new bulk request back end functions
	 * take the inode to start with, so we have to compute the startino
	 * parameter from lastino to maintain correct function.  lastino == 0
	 * is a special case because it has traditionally meant "first inode
	 * in filesystem".
	 */
	if (cmd == XFS_IOC_FSINUMBERS_128) {
		breq.startino = lastino ? lastino + 1 : 0;
		error = xfs_inumbers(&breq, xfs_fsinumbers_fmt);
		lastino = breq.startino - 1;
	} else if (cmd == XFS_IOC_FSBULKSTAT_SINGLE_128) {
		breq.startino = lastino;
		breq.icount = 1;
		error = xfs_bulkstat_one(&breq, xfs_fsbulkstat_one_fmt);
		lastino = breq.startino;
	} else if (cmd == XFS_IOC_FSBULKSTAT_128) {
		breq.startino = lastino ? lastino + 1 : 0;
		error = xfs_bulkstat(&breq, xfs_fsbulkstat_one_fmt);
		lastino = breq.startino - 1;
	} else {
		error = -EINVAL;
	}
	if (error)
		return error;

	if (bulkreq.lastip != NULL &&
	    copy_to_user(bulkreq.lastip, &lastino, sizeof(xfs_ino_t)))
		return -EFAULT;

	if (bulkreq.ocount != NULL &&
	    copy_to_user(bulkreq.ocount, &breq.ocount, sizeof(__s32)))
		return -EFAULT;

	return 0;
}



typedef struct ptr128_xfs_fsop_handlereq {
	 __u32           fd;             /* fd for FD_TO_HANDLE          */
	e2k_ap_t	path;           /* user pathname                */
	 __u32           oflags;         /* open flags                   */
	e2k_ap_t	ihandle;        /* user supplied handle         */
	__u32           ihandlen;       /* user supplied length         */
	e2k_ap_t	ohandle;        /* user buffer for handle       */
	__u32		ohandlen;       /* user buffer length           */
} ptr128_xfs_fsop_handlereq_t;

#define XFS_IOC_PATH_TO_FSHANDLE_128 \
	_IOWR('X', 104, struct ptr128_xfs_fsop_handlereq)
#define XFS_IOC_PATH_TO_HANDLE_128 \
	_IOWR('X', 105, struct ptr128_xfs_fsop_handlereq)
#define XFS_IOC_FD_TO_HANDLE_128 \
	_IOWR('X', 106, struct ptr128_xfs_fsop_handlereq)
#define XFS_IOC_OPEN_BY_HANDLE_128 \
	_IOWR('X', 107, struct ptr128_xfs_fsop_handlereq)
#define XFS_IOC_READLINK_BY_HANDLE_128 \
	_IOWR('X', 108, struct ptr128_xfs_fsop_handlereq)


STATIC int
xfs_ptr128_handlereq_copyin(int cmd,
			    xfs_fsop_handlereq_t		*hreq,
			    ptr128_xfs_fsop_handlereq_t	__user *arg128)
{
	e2k_ap_t ap;
	int	 tag;
	u32	osize;

	switch (cmd) {
	case XFS_IOC_FD_TO_HANDLE_128:
	case XFS_IOC_PATH_TO_HANDLE_128:
	case XFS_IOC_PATH_TO_FSHANDLE_128:
		if (cmd == XFS_IOC_PATH_TO_FSHANDLE_128) {
			osize = sizeof(xfs_fsid_t);
		} else {
			osize = sizeof(xfs_handle_t);
		}
		if (get_user_tagged_16(ap.qword, tag, &arg128->ohandle) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < osize)
			return -EFAULT;
		hreq->ohandle = (void __user *)AP_PTR(ap);
		if (get_user_tagged_16(ap.qword, tag, &arg128->ohandlen) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < sizeof(__u32))
			return -EFAULT;
		hreq->ohandlen = (void __user *)AP_PTR(ap);
		if (get_user_tagged_16(ap.qword, tag, &arg128->path) || !IS_AP(ap, tag))
			return -EFAULT;
		hreq->path = (void __user *)AP_PTR(ap);
		break;
	case XFS_IOC_OPEN_BY_HANDLE_128:
		if (get_user(hreq->ihandlen, &arg128->ihandlen))
			return -EFAULT;
		if (get_user_tagged_16(ap.qword, tag, &arg128->ihandle) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < hreq->ihandlen)
			return -EFAULT;
		hreq->ihandle = (void __user *)AP_PTR(ap);
		if (get_user(hreq->oflags, &arg128->oflags))
			return -EFAULT;
		break;
	case XFS_IOC_READLINK_BY_HANDLE_128: {
		__u32                   olen;
		if (get_user_tagged_16(ap.qword, tag, &arg128->ohandlen) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < sizeof(__u32))
			return -EFAULT;
		hreq->ohandlen =  (void __user *)AP_PTR(ap);
		if (get_user(olen, hreq->ohandlen))
			return -EFAULT;
		if (get_user_tagged_16(ap.qword, tag, &arg128->ohandle) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < olen)
			return -EFAULT;
		hreq->ohandle = (void __user *)AP_PTR(ap);
		if (get_user(hreq->ihandlen, &arg128->ihandlen))
			return -EFAULT;
		if (get_user_tagged_16(ap.qword, tag, &arg128->ihandle) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < hreq->ihandlen)
			return -EFAULT;
		hreq->ihandle = (void __user *)AP_PTR(ap);
		break;
	}
	default:
		return -EINVAL;
	}
	set_u_border(MAX_U_BORDER);
	return 0;
}





static struct dentry *xfs_ptr128_handlereq_to_dentry(struct file		*parfilp,
						     ptr128_xfs_fsop_handlereq_t __user *hreq)
{
	e2k_ap_t ap;
	int	 tag;
	u32	 ihandlen;
	if (get_user(ihandlen, &hreq->ihandlen))
		return ERR_PTR(-EFAULT);
	if (get_user_tagged_16(ap.qword, tag, &hreq->ihandle) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < ihandlen)
		return ERR_PTR(-EFAULT);
	return xfs_handle_to_dentry(parfilp, (void __user *)AP_PTR(ap), ihandlen);
}

typedef struct xfs_attr_multiop128 {
	__u32           am_opcode;
#define ATTR_OP_GET     1       /* return the indicated attr's value */
#define ATTR_OP_SET     2       /* set/create the indicated attr/value pair */
#define ATTR_OP_REMOVE  3       /* remove the indicated attr */
	__s32           am_error;
	e2k_ap_t	am_attrname;
	e2k_ap_t	am_attrvalue;
	__u32           am_length;
	 __u32           am_flags; /* XFS_IOC_ATTR_* */
} xfs_attr_multiop128_t;

typedef struct xfs_fsop_attrmulti_handlereq128 {
	ptr128_xfs_fsop_handlereq_t	hreq; /* handle interface structure */
	 __u32				opcount;/* count of following multiop */
	struct xfs_attr_multiop128         __user *ops; /* array of xfs_attr_multiop128_t */
} xfs_fsop_attrmulti_handlereq128_t;


static int xfs_ptr128_attrmulti_by_handle(struct file	*parfilp,
			xfs_fsop_attrmulti_handlereq128_t __user *arg)
{
	int					error;
	xfs_attr_multiop128_t			*ops;
	xfs_attr_multiop128_t __user		*uops;
	xfs_fsop_attrmulti_handlereq128_t	am_hreq;
	struct dentry				*dentry;
	unsigned int				i, size;
	e2k_ap_t				ap;
	int					tag;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&am_hreq, arg,
			   sizeof(compat_xfs_fsop_attrmulti_handlereq_t)))
		return -EFAULT;

	/* overflow check */
	if (am_hreq.opcount >= INT_MAX / sizeof(xfs_attr_multiop128_t))
		return -E2BIG;

	dentry = xfs_ptr128_handlereq_to_dentry(parfilp, &arg->hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	error = -E2BIG;
	size = am_hreq.opcount * sizeof(xfs_attr_multiop128_t);
	if (!size || size > 16 * PAGE_SIZE)
		goto out_dput;

	if (get_user_tagged_16(ap.qword, tag, &arg->ops) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < size) {
		error = -EFAULT;
		goto out_dput;
	}
	set_u_border(MAX_U_BORDER);
	uops = (void __user *)AP_PTR(ap);
	ops = memdup_user(uops, size);
	if (IS_ERR(ops)) {
		error = PTR_ERR(ops);
		goto out_dput;
	}

	error = -EFAULT;
	for (i = 0; i < am_hreq.opcount; i++) {
		void __user *am_attrname;
		void __user *am_attrvalue;
		if (get_user_tagged_16(ap.qword, tag, &uops[i].am_attrvalue) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < ops[i].am_length) {
			goto free_ops;
		}
		if (get_user_tagged_16(ap.qword, tag, &uops[i].am_attrname) || !IS_AP(ap, tag)) {
			goto free_ops;
		}
		am_attrvalue = (void __user *)AP_PTR(ap);
		ops[i].am_error = xfs_ioc_attrmulti_one(parfilp,
				d_inode(dentry), ops[i].am_opcode,
				am_attrname, am_attrvalue,
				&ops[i].am_length, ops[i].am_flags);
	}

	error = copy_to_user(uops, ops, size);
free_ops:
	kfree(ops);
 out_dput:
	dput(dentry);
	return error;
}




typedef struct {
	struct ptr128_xfs_fsop_handlereq	hreq; /* handle interface structure */
	struct xfs_attrlist_cursor		pos; /* opaque cookie, list offset */
	 __u32					flags;  /* which namespace to use */
	 __u32					buflen; /* length of buffer supplied */
	e2k_ap_t				buffer; /* returned names */
} xfs_fsop_attrlist_handlereq128_t;

#define XFS_IOC_ATTRLIST_BY_HANDLE_128 \
	_NATIVE_IOC(XFS_IOC_ATTRLIST_BY_HANDLE, xfs_fsop_attrlist_handlereq128_t)

static int xfs_ptr128_attrlist_by_handle(struct file		*parfilp,
					 xfs_fsop_attrlist_handlereq128_t __user *p)
{
	xfs_fsop_attrlist_handlereq128_t al_hreq128;
	struct dentry		*dentry;
	e2k_ap_t		ap;
	int			tag;
	int			error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&al_hreq128, p, sizeof(al_hreq128)))
		return -EFAULT;

	dentry = xfs_ptr128_handlereq_to_dentry(parfilp, &p->hreq);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	if (get_user_tagged_16(ap.qword, tag, &p->buffer) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < al_hreq128.buflen) {
		dput(dentry);
		return -EFAULT;
	}
	set_u_border(MAX_U_BORDER);
	error = xfs_ioc_attr_list(XFS_I(d_inode(dentry)),
			(void __user *)AP_PTR(ap), al_hreq128.buflen,
			al_hreq128.flags, &p->pos);
	dput(dentry);
	return error;
}





long
xfs_file_ptr128_ioctl(
	struct file		*filp,
	unsigned		cmd,
	unsigned long		p)
{
	struct inode		*inode = file_inode(filp);
	struct xfs_inode	*ip = XFS_I(inode);
	void			__user *arg = (void __user *)p;
	struct xfs_fsop_handlereq	hreq;


	switch (cmd) {
	case XFS_IOC_FSBULKSTAT_128:
	case XFS_IOC_FSBULKSTAT_SINGLE_128:
	case XFS_IOC_FSINUMBERS_128:
		return xfs_ptr128_ioc_fsbulkstat(filp, cmd, arg);
	case XFS_IOC_FD_TO_HANDLE_128:
	case XFS_IOC_PATH_TO_HANDLE_128:
	case XFS_IOC_PATH_TO_FSHANDLE_128: {
		if (xfs_ptr128_handlereq_copyin(cmd, &hreq, arg))
			return -EFAULT;
		return xfs_find_handle(_NATIVE_IOC(cmd, struct xfs_fsop_handlereq), &hreq);
	}
	case XFS_IOC_OPEN_BY_HANDLE_128: {
		if (xfs_ptr128_handlereq_copyin(cmd, &hreq, arg))
			return -EFAULT;
		return xfs_open_by_handle(filp, &hreq);
	}
	case XFS_IOC_READLINK_BY_HANDLE_128: {
		if (xfs_ptr128_handlereq_copyin(cmd, &hreq, arg))
			return -EFAULT;
		return xfs_readlink_by_handle(filp, &hreq);
	}
	case XFS_IOC_ATTRLIST_BY_HANDLE_128:
		return xfs_ptr128_attrlist_by_handle(filp, arg);
	case XFS_IOC_ATTRMULTI_BY_HANDLE_32:
		return xfs_ptr128_attrmulti_by_handle(filp, arg);
	default:
		/* try the native version */
		return xfs_file_ioctl(filp, cmd, (unsigned long)arg);
	}
}
