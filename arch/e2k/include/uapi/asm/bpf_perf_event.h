/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#pragma once

#ifdef __KERNEL__
/* Attention!!! This structure must be the same as user_pt_regs from <asm/ptrace.h> */
#endif /* __KERNEL__ */
typedef struct {} bpf_user_pt_regs_t;
