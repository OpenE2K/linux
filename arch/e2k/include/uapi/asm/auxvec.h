/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2026 MCST
 */

#ifndef _E2K_AUXVEC_H
#define _E2K_AUXVEC_H

#define AT_FAST_SYSCALLS 32
#define AT_SYSINFO_EHDR  33
#define AT_SYSTEM_INFO   34
#define AT_BINCOMP_INFO  35

#ifdef __KERNEL__
# define AT_VECTOR_SIZE_ARCH 3
#endif

#endif	/* _E2K_AUXVEC_H */
