/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains all common values for cBPF templates and JIT compiler.
 */

#pragma once

#define E2K_CBPF_JIT

#include "bpf_jit_label_naming.h"

#ifdef __ASSEMBLY__
# include "bpf_jit_asm_common.h"
#else /* __ASSEMBLY__ */
# include "bpf_jit_comp_lib.h"
#endif /* __ASSEMBLY__ */

