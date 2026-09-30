/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_DEVTREE_H
#define _ASM_L_DEVTREE_H
#include <linux/types.h>

extern int e2k_apply_device_tree_patches(void);
extern void early_device_tree_init(void);
extern void device_tree_init(void);

#ifdef CONFIG_DTB_L_TEST
extern unsigned char test_blob[];
#endif

#endif /* _ASM_L_DEVTREE_H */
