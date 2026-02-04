/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains all common values for eBPF templates and JIT compiler.
 */

#pragma once

#define E2K_EBPF_JIT

#include "bpf_jit_label_naming.h"

#ifdef __ASSEMBLY__
# include "bpf_jit_asm_common.h"
#else /* __ASSEMBLY__ */
# include "bpf_jit_comp_lib.h"
#endif /* __ASSEMBLY__ */

/*
 * For almost all eBPF instructions source and destination registers (src and dst)
 * are encoded in the instruction itself. Technically, it is possible to mark
 * all wide instructions in templates with corresponding labels so that JIT can
 * change src and dst like any other labeled items - constants, offsets,
 * displacements, etc. But this will result in a huge number of different labels
 * throughout templates, so another approach was chosen.
 *
 * In templates, src and dst registers have big serial numbers, which are exactly
 * out of register window bounds. So JIT during copying a template can easily check
 * all ALS syllables and substitute these big register numbers with correct numbers
 * obtained from eBPF instruction.
 */
#define EBPF_JIT_SRC_REG 60
#define EBPF_JIT_DST_REG 61

/*
 * eBPF JIT stores a special number right before the start of jited program
 * (image). This number can be easily obtained by the program that prepares to
 * make a tail call. Let's call this number 'tail call offset'. It tells the
 * program that is ready to make tail call how many leading bytes of the callee
 * code should be skiped during tail call. The number of skipped bytes is
 * actually the length of the first part of prologue, namely tail call counter
 * zeroing. Its length depends both on the length of corresponding template and
 * (the most annoying thing!) on the length of nops inserted due to HW bug
 * workaround, thus the tail call offset is quite random. That's why a nasty
 * hack with storing the tail call offset before the image was done. To sum up,
 * eBPF JIT calculates tail call offset during compilation of eBPF program A and
 * stores it before A's image, and eBPF program B loads this shift before making
 * a tail call to A and corrects jump displacement to jump over A's tail call
 * counter zeroing. Note, that JIT does not emit tail call counter zeroing for
 * eBPF subprograms, consequently their tail call offset is always 0.
 *
 * This macro is the distance between the start of image and the place where
 * tail call offset is stored. Note that this size should be enough to store an
 * integer value and should not change the alignment in image, which is 8 in e2k.
 * There are several compile-time checks in the compiler code that check the
 * conditions mentioned above.
 */
#define TAIL_CALL_OFFSET_SIZE 8

