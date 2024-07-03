/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel-based Virtual Machine MMU driver for e2k V6/old Page Tables support
 */

#include "mmu-pt.h"

#define	PT_TYPE		E2K_PT_V6_OLD
#include "mmu-pt-tmpl.c"
#undef	PT_TYPE
