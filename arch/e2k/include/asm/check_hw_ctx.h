/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#pragma once

#include <linux/types.h>
#include <asm/e2k_ptypes.h>
#include <asm/errno.h>

/* Check if specified tag for qword is possible */
static inline bool is_possible_qtag(u8 qtag)
{
	u8 tag0 = qtag & 0x3, tag1 = (qtag >> 2) & 0x3,
	   tag2 = (qtag >> 4) & 0x3, tag3 = (qtag >> 6) & 0x3;

	if (cpu_has(CPU_FEAT_ISET_V6)) {
		if (tag0 == 2 || tag1 == 2 || tag2 == 2 || tag3 == 2)
			return false;
	} else {
		if (tag2 == 3)
			return false;
	}

	return true;
}

/*
 * Check that it val_lo, val_hi, tag don't constitute
 * descriptor pointing to privileged area
 */
static inline bool is_priv_desc(u64 val_lo, u64 val_hi, u32 tag)
{
	e2k_ap_t ptr_desc = {
		.lo = val_lo,
		.hi = val_hi
	};

	e2k_pl_t pl_desc = {
		.lo = val_lo,
		.hi = val_hi
	};

	if (!is_possible_qtag(tag))
		return true;

	if (IS_AP(ptr_desc, tag) && !__range_ok(AP_BASE(ptr_desc),
			AP_SIZE(ptr_desc), user_addr_max()))
		return true;

	if (IS_PL(pl_desc, tag) && pl_desc.target >= user_addr_max())
		return true;

	return false;
}

static inline int check_user_gregs(size_t count, const u64 *g, const u8 *gtag)
{
	BUG_ON(count % 2);
	for (int i = 0; i < count; i += 2) {
		if (is_priv_desc(g[i], g[i + 1], gtag[i] | (gtag[i + 1] << 4)))
			return -EPERM;
	}

	return 0;
}
