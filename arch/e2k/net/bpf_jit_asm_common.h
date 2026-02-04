/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains common definitions for cBPF and eBPF templates.
 */

#pragma once

#include <linux/linkage.h>

/*
 * A template is a piece of assembly code (mostly containing several e2k wide
 * instructions) that is compiled with kernel sources. For every BPF instruction
 * there is a corresponding template, so JIT just finds it and copies the
 * object code of the template to a previously allocated memory (called
 * 'image').
 */

/*
 * As JIT needs to change some of templates (e.g. to insert constants from BPF
 * program or to set up jumps in the compiled program), special labels were
 * added to mark the wide instructions where JIT should make changes.
 *
 * This macro declares a label in a template.
 */
#define BPF_TEMPL_LABEL(name) SYM_INNER_LABEL(name, SYM_L_GLOBAL)


/*
 * We need to introduce a finishing label in order to be able to get the length
 * of a template.
 * There is a standard kernel mechanism called kallsyms which can calculate
 * the size of a symbol by computing a distance between addresses of the
 * current and the next symbol. However, this approach fails when there are
 * labels in the template code, so we have to define a finishing label for
 * every template to be able to get the size of this template.
 */
#define SYM_FUNC_START_SIZED(templ) SYM_FUNC_START(templ)
#define SYM_FUNC_END_SIZED(templ)				\
	BPF_TEMPL_LABEL(BPF_JIT_FUNC_END_LABEL(templ)) ASM_NL	\
	SYM_FUNC_END(templ)

