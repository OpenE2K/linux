/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_SECCOMP_H
#define _ASM_SECCOMP_H

#include <asm/unistd.h>

#include <asm-generic/seccomp.h>

#define SECCOMP_ARCH_NATIVE		AUDIT_ARCH_E2K
#define SECCOMP_ARCH_NATIVE_NR		NR_syscalls
#define SECCOMP_ARCH_NATIVE_NAME	"e2k"
#ifdef CONFIG_COMPAT
# define SECCOMP_ARCH_COMPAT		AUDIT_ARCH_E2K
# define SECCOMP_ARCH_COMPAT_NR		NR_syscalls
# define SECCOMP_ARCH_COMPAT_NAME	"e2k"
#endif /* CONFIG_COMPAT */

#endif /* _ASM_SECCOMP_H */
