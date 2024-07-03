/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _LINUX_PROT_COMPAT_H
#define _LINUX_PROT_COMPAT_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#ifdef CONFIG_PROTECTED_MODE

#include <linux/types.h>
#include <linux/time.h>

#include <linux/stat.h>
#include <linux/param.h>	/* for HZ */
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/fs.h>
#include <linux/aio_abi.h>	/* for aio_context_t */
#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/siginfo.h>
#include <asm/signal.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
/*
 * It may be useful for an architecture to override the definitions of the
 * COMPAT_SYSCALL_DEFINE0 and COMPAT_SYSCALL_DEFINEx() macros, in particular
 * to use a different calling convention for syscalls. To allow for that,
 + the prototypes for the compat_sys_*() functions below will *not* be included
 * if CONFIG_ARCH_HAS_SYSCALL_WRAPPER is enabled.
 */
#include <asm/syscall_wrapper.h>
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */


struct prot_stack {
	e2k_ptr_t ss_sp;
	int ss_flags;
	size_t ss_size;
};


struct prot_iovec {
	e2k_ptr_t	iov_base;
	__kernel_size_t iov_len;
};

struct protected_user_msghdr {
	e2k_ptr_t	msg_name;	/* ptr to socket address structure */
	int		msg_namelen;	/* size of socket address structure */
	e2k_ptr_t	msg_iov;	/* scatter/gather array */
	__kernel_size_t msg_iovlen;	/* # elements in msg_iov */
	e2k_ptr_t	msg_control;	/* ancillary data */
	__kernel_size_t msg_controllen;	/* ancillary data buffer length */
	unsigned int    msg_flags;	/* flags on received message */
};

struct protected_mmsghdr {
	struct protected_user_msghdr msg_hdr;  /* Message header */
	unsigned int  msg_len;  /* Number of received bytes for header */
};


#endif /* CONFIG_PROTECTED_MODE */

#endif
