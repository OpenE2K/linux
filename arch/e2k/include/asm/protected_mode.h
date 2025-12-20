/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/****************** E2K PROTECTED MODE SPECIFIC STUFF *******************/

#ifndef _E2K_ASM_PROTECTED_MODE_H_
#define _E2K_ASM_PROTECTED_MODE_H_

#include <uapi/asm/protected_mode.h>

/*
 * This structure specifies attributes of protected syscall arguments:
 */
struct prot_syscall_arg_attrs {
	u64  mask; /* for coding specs see prot_sys_call_synopsis.c */
	/* The next 6 fields specify minimum allowed argument size
	 *                          in case of argument-descriptor.
	 * If negative value, this means size is defined by corresponding arg.
	 *             F.e. value (-3) means size is specified by argument #3.
	 */
	short size1; /* min allowed size of arg1 of particular system call */
	short size2; /* minimum allowed size of arg2  */
	short size3; /* minimum allowed size of arg3  */
	short size4; /* minimum allowed size of arg4  */
	short size5; /* minimum allowed size of arg5  */
	short size6; /* minimum allowed size of arg6  */
} __aligned(sizeof(void *)) /* For faster address calculation */;
extern const struct prot_syscall_arg_attrs prot_syscall_arg_masks[];

#endif /* _E2K_ASM_PROTECTED_MODE_H_ */
