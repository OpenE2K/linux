/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Common templates for cBPF and eBPF JIT compilers.
 */

#include "bpf_jit_label_naming.h"
#include "bpf_jit_asm_common.h"

/*
 * CPU_HWBUG_JUMP: as HW bug 146897 workaround is implemented by JIT,
 * the templates in this file need no workaround. This assembler
 * directive turns the workaround off.
 */
#if __iset__ <= 6
.fix_lcc_bug149113
#endif

/*
 * This file contains only templates. They are copied by JIT to another
 * location before being executed. So mark all templates as read-only.
 */
.section .rodata

/* Template for filling allocated memory with illegal instructions */
SYM_FUNC_START_SIZED(bpf_jit_fill_setsft)
{
	setsft
}
SYM_FUNC_END_SIZED(bpf_jit_fill_setsft)

