/*
 * Kernel-based Virtual Machine MMU driver for e2k V6/gp Page Tables support
 *
 * Copyright 2021 MCST.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "mmu-pt.h"

#define	PT_TYPE		E2K_PT_V6_GP
#include "mmu-pt-tmpl.c"
#undef	PT_TYPE
