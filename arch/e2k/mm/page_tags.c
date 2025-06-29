/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/base_regs_types.h>
#include <asm/page_tags.h>
#include <asm/mmu_fault.h>
#include <asm/pgtable.h>


u32 save_tags_from_data(u64 *datap, u8 *tagp)
{
	u32 res = 0;
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		e2k_qreg_t value;
		u8 tag;

		load_qvalue_and_tagq(&datap[2 * i], &value, &tag, 8);

		tagp[i] = tag;
		res |= tag;
	}

	return res;
}

void restore_tags_for_data(u64 *datap, u8 *tagp)
{
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		u64 data_lo = datap[2 * i], data_hi = datap[2 * i + 1];
		u32 tag = (u32) tagp[i];

		store_tagged_dword(&datap[2 * i], data_lo, tag);
		store_tagged_dword(&datap[2 * i + 1], data_hi, tag >> 4);
	}
}

