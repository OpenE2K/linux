/*
 * Copyright (C) 2010 Nouveau Project
 * Copyright (c) 2012-2013 ZAO "MCST". All rights reserved.
 *
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */
/*
 * Authors: Alexander Troosh <troosh@mcst.ru>
 */

#include <linux/ratelimit.h>

//#include "drm.h"
#include "drmP.h"

#include "mcst_drv.h"
#include "mcst_util.h"

static DEFINE_RATELIMIT_STATE(mcst_ratelimit_state, 3 * HZ, 20);

void
mcst_bitfield_print(const struct mcst_bitfield *bf, u32 value)
{
	u32 mask;

	while (bf->name) {
		mask = ((1<<bf->size) - 1) << bf->pos;
		if (value & mask) {
			if (bf->size == 1) {
				pr_cont("%s ", bf->name);
			} else {
				pr_cont("%s=0x%x ", bf->name,
						(value & mask) >> bf->pos);
			}
			value &= ~mask;
		}
		bf++;
	}
	pr_info("\n");

	if (value)
		DRM_ERROR(" (unknown bits 0x%08x)", value);
}

const struct mcst_enum *
mcst_enum_find(const struct mcst_enum *en, u32 value)
{
	while (en->name) {
		if (en->value == value)
			return en;
		en++;
	}

	return NULL;
}

void
mcst_enum_print(const struct mcst_enum *en, u32 value)
{
	en = mcst_enum_find(en, value);
	if (en) {
		DRM_INFO("%s", en->name);
		return;
	}

	DRM_ERROR("(unknown enum 0x%08x)", value);
}

int
mcst_ratelimit(void)
{
	return __ratelimit(&mcst_ratelimit_state);
}

void mcst_hexdump_regs(struct mcst_private *mcst, int cell)
{
	int addr;

	pr_info("Registers of cell #%d (virt_addr=%p phys_addr=0x%lx)\n",
			cell, mcst->ioregs[cell],
			pci_resource_start(mcst->dev->pdev,
				PCI_MGA_FBMEM_BAR)+0x2000*cell);

	for (addr = 0; addr < 0x1000; addr += 4) {
		if ((addr & 15) == 0)
			pr_cont("\n%04x:", addr);
		pr_cont(" %08x", mcst_io_read32(mcst, cell, addr));
	}
	pr_cont("\n");
}

