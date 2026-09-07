/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_PROTOTYPES_H
#define __ASM_PROTOTYPES_H

#include <asm-generic/asm-prototypes.h>
extern unsigned long __recovery_memcpy_8(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode, int prefetch);
extern unsigned long __recovery_memcpy_16(void *dst, const void *src, size_t len,
		unsigned long strqp_opcode, unsigned long ldrqp_opcode, int prefetch);

#endif /* __ASM_PROTOTYPES_H */
