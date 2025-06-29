/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * There is only one common non-'inline' function for both cBPF and eBPF JIT
 * compilers. It fills image with illegal instruction when passed as argument
 * to arch-independent image allocator, so we can not declare it 'inline'
 * and put into header file.
 */

#include <linux/types.h>
#include <linux/linkage.h>
#include <asm/string.h>

#include "bpf_jit_comp_common.h"

BPF_JIT_EXTERN_TEMPLATE(bpf_jit_fill_setsft);

/*
 * Fill `size' bytes starting at `area' with illegal instructions.
 */
void jit_fill_exc_software_trap(void *area, unsigned int size)
{
	void *ptr = area;
	unsigned int template_size = BPF_JIT_TEMPLATE_SIZE(bpf_jit_fill_setsft);

	while (ptr + template_size <= area + size) {
		memcpy(ptr, &bpf_jit_fill_setsft, template_size);
		ptr += template_size;
	}
}

