/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

#include <linux/linkage.h>

#include <asm/asm-offsets.h>
#include <asm/export.h>


.text
.ignore ld_st_style
SYM_FUNC_START(colored_page_copy)
	{
		setwd wsz = 0x2a, nfx = 0
		setbn rsz = 0x23, rbs = 6, rcur = 0x0

		ipd 1
		disp %ctpr1, 1f /* copy_head */

		rwd 9 | E2K_LSR_VLC, %lsr

		addd,1 %dr1, 0x20, %dr2
		addd,4 %dr1, 0x20, %dr3
	}
	{
		ipd 1
		disp %ctpr2, 2f /* prefetch */

		addd,1    0, TAGGED_MEM_LOAD_REC_OPC_BYPASS_L1, %dr8
		addd,4 0x10, TAGGED_MEM_LOAD_REC_OPC_BYPASS_L1, %dr9

		addd,2    0, COLORED_MEM_LOAD_REC_OPC_BYPASS_L1, %dr10
		addd,5 0x10, COLORED_MEM_LOAD_REC_OPC_BYPASS_L1, %dr11
	}
	{
		ldrqp,0 [ %dr1 + %dr8 ], %db[6]
		ldrqp,3 [ %dr1 + %dr9 ], %db[7]
		ldrd,2 [ %dr1 + %dr10 ], %db[30]
		ldrd,5 [ %dr1 + %dr11 ], %db[31]
	}
	{
		ldrqp,0 [ %dr2 + %dr8 ], %db[4]
		ldrqp,3 [ %dr3 + %dr9 ], %db[5]
		ldrd,2 [ %dr2 + %dr10 ], %db[28]
		ldrd,5 [ %dr3 + %dr11 ], %db[29]
		addd,1 %dr2, 0x20, %dr2
		addd,4 %dr3, 0x20, %dr3
	}
	{
		ldrqp,0 [ %dr2 + %dr8 ], %db[2]
		ldrqp,3 [ %dr3 + %dr9 ], %db[3]
		ldrd,2 [ %dr2 + %dr10 ], %db[26]
		ldrd,5 [ %dr3 + %dr11 ], %db[27]
		addd,1 %dr2, 0x20, %dr2
		addd,4 %dr3, 0x20, %dr3
	}
1: /* copy_head */
	{
		ldrqp,0 [ %dr2 + %dr8 ], %db[0]
		ldrqp,3 [ %dr3 + %dr9 ], %db[1]
		ldrd,2 [ %dr2 + %dr10 ], %db[24]
		ldrd,5 [ %dr3 + %dr11 ], %db[25]
		addd,1 %dr2, 0x20, %dr2
		addd,4 %dr3, 0x20, %dr3

		abn abnf = 0, abnt = 1
		alc alcf = 0, alct = 1
		ct %ctpr1 ? %NOT_LOOP_END
	}

	{
		ipd 1
		disp %ctpr1, 3f /* copy */

		rwd 11 | E2K_LSR_VLC, %lsr

		addd,1 %dr1, 0x200, %dr4
		addd,4 %dr1, 0x280, %dr5
	}

	/* Load the src block into the L2 cache - prefetching to L1
	 * is neither practical (only 1 line is fetched per cycle)
	 * nor needed (this loop is unrolled enough to do not worry
	 * about latency). */
	{
		return %ctpr3

		ldb,3,sm %dr1, 0x180, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,5,sm %dr1, 0x1c0, %empty, mas=MAS_BYPASS_L1_CACHE
	}
	{
		ldb,0,sm %dr4,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,2,sm %dr4, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,3,sm %dr5,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,5,sm %dr5, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		addd,1 %dr4, 0x100, %dr4
		addd,4 %dr5, 0x100, %dr5
	}
	{
		ldb,0,sm %dr4,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,2,sm %dr4, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,3,sm %dr5,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,5,sm %dr5, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		addd,1 %dr4, 0x100, %dr4
		addd,4 %dr5, 0x100, %dr5
	}
	{
		ldb,0,sm %dr4,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,2,sm %dr4, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,3,sm %dr5,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,5,sm %dr5, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		addd,1 %dr4, 0x100, %dr4
		addd,4 %dr5, 0x100, %dr5
	}
2: /* prefetch */
	{
		ldb,0,sm %dr4,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,2,sm %dr4, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,3,sm %dr5,  0x0, %empty, mas=MAS_BYPASS_L1_CACHE
		ldb,5,sm %dr5, 0x40, %empty, mas=MAS_BYPASS_L1_CACHE
		addd,1 %dr4, 0x100, %dr4
		addd,4 %dr5, 0x100, %dr5

		alc alcf = 0, alct = 1
		ct %ctpr2 ? %NOT_LOOP_END
	}

	/* Copy the page */
	{
		ipd 1
		disp %ctpr2, 4f /* copy_tail */

		rwd (128 - 12) | E2K_LSR_VLC, %lsr

		addd,1    0, COLORED_MEM_STORE_REC_OPC_BYPASS_L1, %dr4
		addd,4 0x10, COLORED_MEM_STORE_REC_OPC_BYPASS_L1, %dr5
	}
	{
		insfd,1 %db[46], 4 /*shift*/ | (60 /*size*/ << 6), %dr0, %dr6
		insfd,4 %db[47], 3 /*shift*/ | (61 /*size*/ << 6), %dr0, %dr7
	}
3: /* copy */
	{
		/* CPU_HWBUG_TAGGED_STRQP: strqp must be speculative
		 * if dealing with tags */
		strqp,2,sm [ %dr6 + %dr4 ], %db[22]
		strqp,5,sm [ %dr7 + %dr5 ], %db[23]
		addd,1 %dr4, 0x20, %dr4
		addd,4 %dr5, 0x20, %dr5
		insfd,0 %db[44], 4 /*shift*/ | (60 /*size*/ << 6), %dr0, %dr6
		insfd,3 %db[45], 3 /*shift*/ | (61 /*size*/ << 6), %dr0, %dr7
		abn abnf = 1, abnt = 1
	}
	{
		ldrqp,0 [ %dr2 + %dr8 ], %db[0]
		ldrqp,3 [ %dr3 + %dr9 ], %db[1]
		ldrd,2 [ %dr2 + %dr10 ], %db[24]
		ldrd,5 [ %dr3 + %dr11 ], %db[25]
		addd,1 %dr2, 0x20, %dr2
		addd,4 %dr3, 0x20, %dr3

		alc alcf = 0, alct = 1
		ct %ctpr1 ? %NOT_LOOP_END
	}
	/* Copy the remaining tail */
	{
		nop 4
		rwd 12 | E2K_LSR_VLC, %lsr
	}
4: /* copy_tail */
	{
		strqp,2,sm [ %dr6 + %dr4 ], %db[22]
		strqp,5,sm [ %dr7 + %dr5 ], %db[23]
		addd,1 %dr4, 0x20, %dr4
		addd,4 %dr5, 0x20, %dr5
		// Speculative because on the last iteration (%NOT_LOOP_END=false)
		// registers db[44]/db[45] can contain any value
		insfd,0,sm %db[44], 4 /*shift*/ | (60 /*size*/ << 6), %dr0, %dr6
		insfd,3,sm %db[45], 3 /*shift*/ | (61 /*size*/ << 6), %dr0, %dr7

		abn abnf = 0, abnt = 1
		alc alcf = 0, alct = 1
		ct %ctpr2 ? %NOT_LOOP_END
	}
	{
		ct %ctpr3
	}
SYM_FUNC_END(colored_page_copy)
EXPORT_SYMBOL_GPL(colored_page_copy)