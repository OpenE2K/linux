/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains naming patterns for template labels.
 */

#pragma once

/*
 * Exclusive naming patterns for eBPF JIT compiler.
 */
#if defined(E2K_EBPF_JIT)
# define BPF_JIT_JMP_LABEL(templ) templ##_jmp_cs0

# define BPF_JIT_FUNC_LABEL(templ) templ##_func_cs0
# define BPF_JIT_WBS_LABEL(templ) templ##_wbs_cs1

# define BPF_JIT_IMM_LABEL(templ) templ##_imm_lts0
# define BPF_JIT_OFF_LABEL(templ) templ##_off_lts0

# define BPF_JIT_STACK_SIZE_LABEL(templ) templ##_stack_size_lts1
#endif

/*
 * Exclusive naming patterns for cBPF JIT compiler.
 */
#if defined(E2K_CBPF_JIT)
# define BPF_JIT_K_LABEL(templ) templ##_k_lts0

# define BPF_JIT_JMP_LABEL(templ, cond) templ##_##cond##_cs0

# define BPF_JIT_FUNC_LABEL(templ, func) templ##_##func##_cs0
# define BPF_JIT_WBS_LABEL(templ, func) templ##_wbs_##func##_cs1

# define BPF_JIT_MEM_LABEL(templ, field) templ##_als0_##field
# define BPF_JIT_MEM_SRC_LABEL(templ) BPF_JIT_MEM_LABEL(templ, src2)
# define BPF_JIT_MEM_DST_LABEL(templ) BPF_JIT_MEM_LABEL(templ, dst)
#endif

/*
 * Common naming patterns for both eBPF and cBPF JIT compilers.
 */
#define BPF_JIT_WSZ_LABEL(templ) templ##_wsz_lts0
#define BPF_JIT_RBS_LABEL(templ) templ##_rbs_cs1
#define BPF_JIT_FUNC_END_LABEL(templ) templ##_end

