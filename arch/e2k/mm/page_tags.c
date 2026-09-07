/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/base_regs_types.h>
#include <asm/page_tags.h>
#include <asm/mmu_fault.h>
#include <asm/pgtable.h>


u32 save_tags_colors_from_data(u64 *datap, u8 *tagp, u8 *clrp)
{
	u32 res = 0;
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		e2k_qreg_t value;
		u8 tag;

		load_qvalue_and_tagq(&datap[2 * i], &value, &tag, 8);

		tagp[i] = tag;
		res |= tag;
#ifdef CONFIG_PROTECTED_MODE
		if (cpu_has(CPU_FEAT_ISET_V7)) {
			u8 clr;
			// get color of datap[2 * i] chunk */
			clr = __kernel_ldrd_d_opc(&datap[2 * i],
				(ldst_rec_op_t) { .fmt_h = LDST_MCOLOR_FMT_H});
			clrp[i / 2] = (i & 1) ? ((clrp[i / 2] | (clr << 4))) : clr;
			res |= clr;
		}
#endif
	}

	return res;
}

void restore_tags_colors_for_data(u64 *datap, u8 *tagp, u8 *clrp)
{
	int i;

	for (i = 0; i < (int) TAGS_BYTES_PER_PAGE; i++) {
		u64 ptr_to_store = (u64)&datap[2 * i];
		e2k_qreg_t data = (e2k_qreg_t) {
			.lo = datap[2 * i],
			.hi = datap[2 * i + 1],
		};

#ifdef CONFIG_PROTECTED_MODE
		if (cpu_has(CPU_FEAT_ISET_V7)) {
			u8 clr = (i & 1) ? (clrp[i / 2] >> 4) : (clrp[i / 2] & 0xf);
			if (clr) {
				ptr_to_store = ptr_to_store | (clr << ((i & 1) ? 61 : 60));
			}
			store_tagged_colored_qword((void *)ptr_to_store, data, tagp[i]);
		} else
#endif
			store_tagged_qword((void *)ptr_to_store, data, tagp[i], 8);
	}
}

