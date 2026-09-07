/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#ifndef _ASM_E2K_KASAN_H
#define _ASM_E2K_KASAN_H

#include <linux/const.h>
#define KASAN_SHADOW_OFFSET _UL(CONFIG_KASAN_SHADOW_OFFSET)
#define KASAN_SHADOW_SCALE_SHIFT 3

/* Place shadow memory in 0xf600_0000_0000 - 0xfe00_0000_0000
 * This range is big enough to cover both PAGE_OFFSET and VMALLOC areas. */
#define KASAN_SHADOW_START ((PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT) + \
			    KASAN_SHADOW_OFFSET)
#define KASAN_SHADOW_SIZE  _UL(0x80000000000)
#define KASAN_SHADOW_END   (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)

#ifdef CONFIG_KASAN
void __init kasan_early_init(void);
void __init kasan_init(void);
#else
static inline void kasan_early_init(void) { }
static inline void kasan_init(void) { }
#endif

#endif
