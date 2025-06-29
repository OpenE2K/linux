/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once
#include <linux/types.h>

extern int mem_set_empty_tagged_dw(void __user *ptr, s64 size, u64 dw);
extern int clean_descriptors(void __user *list, unsigned long list_size);
extern int clean_single_descriptor(e2k_ptr_t descriptor);
