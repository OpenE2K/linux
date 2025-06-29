/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains definitions of macros for work with templates.
 */

#pragma once

#include <linux/math.h>
#include <asm/cpu_regs.h>
#include <asm/cpu_features.h>

#include "bpf_jit_label_naming.h"

/*
 * Return the length of a template `templ'. The length of a template is a
 * distance between its start and its finishing label.
 */
#define BPF_JIT_TEMPLATE_SIZE(templ) \
	((int)((unsigned long) BPF_JIT_FUNC_END_LABEL(templ) - \
	       (unsigned long) templ))

/*
 * Return the distance from the beginning of template `templ' to label `label'.
 */
#define BPF_JIT_OFFSET(label, templ) \
	((int)((long)label - (long)templ))

/*
 * Each assembler template has a finishing label so that its length can be
 * obtained correctly. The macro below is used in C code to declare both
 * template and its finishing label in one line.
 */
#define BPF_JIT_EXTERN_TEMPLATE(templ) \
	asmlinkage void templ(void); \
	extern char BPF_JIT_FUNC_END_LABEL(templ)[]

extern void jit_fill_exc_software_trap(void *area, unsigned int size);

