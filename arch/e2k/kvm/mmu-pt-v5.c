/*
 * Kernel-based Virtual Machine MMU driver for e2k V5 Page Tables support
 *
 * Copyright 2021 MCST.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "mmu-pt.h"

#define	PT_TYPE		E2K_PT_V5
#include "mmu-pt-tmpl.c"
#undef	PT_TYPE
