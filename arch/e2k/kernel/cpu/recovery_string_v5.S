/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>

.text
.global $__recovery_memcpy_16
.type __recovery_memcpy_16,@function
$__recovery_memcpy_16:
.ignore ld_st_style
/*
 * dr0 - dst
 * dr1 - src
 * dr2 - len
 * dr3 - strqp opcode
 * dr4 - ldrqp opcode
 * r5 - enable prefetching
 *
 * Does not return a value.
 */
	{
		setwd wsz = 0x16, nfx = 0
		ipd 1
		disp %ctpr2, 5f /* very_small_size */

		setbn rsz = 0xb, rbs = 0xa, rcur = 0x0
		setbp psz = 0x1

		/* dr16 holds ldrd opcode for prefetching from address which
		 * is known to be good - i.e. is from (src; src+len) range.
		 * First get 'prot' bit from passed ldrd opcode. */
		andd,2 %dr4, 0x8000000000, %dr16

		/* dr14 holds the number of copied bytes
		 * in case pagefault happens */
		addd,4 0x0, 0x0, %dr14

		addd,3 %dr4, 0x0, %dr10
		addd,5 %dr4, 0x10, %dr11
	}
	{
		ipd 1
		disp %ctpr1, 6f /* small_size */

		/* Use 1-byte loads into L2 for prefetch */
		ord,2 %dr16, 0x12000000000, %dr16

		addd,5 %dr4, 0x20, %dr12

		/* %pred26 == 'true' if 'size' is zero (i.e. 'size' < 16) */
		cmpbdb,0 %dr2, 0x10, %pred26
		/* %pred27 == 'false' if 'size' >= 32 bytes */
		cmpbdb,1 %dr2, 0x20, %pred27

		/* %pred28 == 'false' if 'size' >= 48 bytes */
		cmpbdb,3 %dr2, 0x30, %pred28
		/* %pred25 == 'true' if 'size' <= 64 bytes */
		cmpledb,4 %dr2, 0x40, %pred25
	}
	{
		return %ctpr3

		addd,5 %dr4, 0x30, %dr13

		cmpbdb,0 %dr2, 0x80, %pred12
		/* %pred29 == 'false' if 'size' >= 64 bytes */
		cmpbdb,1 %dr2, 0x40, %pred29

		/* If %pred6 is 'false' then the remaining 32-bytes
		 * tail has to be copied after the main copying loop
		 * which copies data in 64-bytes blocks. */
		cmpandedb,3 %dr2, 0x20, %pred6
		/* %pred7 == 'size' < 384 (minimum allowed size
		 * for the optimized copying algorythm - 12 cachelines
		 * for unrolling) */
		cmpbdb,4 %dr2, 0x180, %pred7
	}
	{
		/* %pred8 == 'true' if 'size' is a multiple of 32 */
		cmpandedb,1 %dr2, 0x10, %pred8

		addd,0 %dr3, 0x0, %dr6
		addd,2 %dr3, 0x20, %dr8

		addd,4 %dr3, 0x10, %dr7

		ldrqp,3 [ %dr1 + %dr10 ], %db[10] ? ~ %pred26
		ldrqp,5 [ %dr1 + %dr11 ], %db[11] ? ~ %pred27
	}
	{
		addd,4 %dr3, 0x30, %dr9

		ldrqp,3 [ %dr1 + %dr12 ], %db[22] ? ~ %pred28
		ldrqp,5 [ %dr1 + %dr13 ], %db[23] ? ~ %pred29

		ct %ctpr2 ? %pred25
	}
	{
		ipd 0
		disp %ctpr2, 8f /* copy_tail_small */

		addd,1 %dr1, 0x1a0, %db[0]

		/* Check whether prefetching is disabled */
		cmpesb,4 %r5, 0, %pred15

		addd,0 %dr1, 0x40, %dr5
		addd,2 %dr1, 0x80, %dr4

		addd,5 %dr1, %dr2, %dr3

		/* If the block is small, use simple loop without unrolling */
		ct %ctpr1 ? %pred7
	}
	{
		ipd 0
		disp %ctpr3, 2f /* skip_prefetch_loop */

		/* pred2 = not enough data for 1 prefetch iteration =
		 *       = left_to_prefetch <= 0x1c0 =
		 *       = dr1 + dr2 - db[0] <= 0x1c0 =
		 *       = dr1 + dr2 - (dr1 + 0x1a0) <= 0x1c0 =
		 *       = dr2 <= 0x360 */
		cmpbedb,4 %dr2, 0x360, %pred2

		ldrqp,0 [ %dr5 + %dr10 ], %db[8]
		ldrqp,2 [ %dr5 + %dr11 ], %db[9]
		ldrqp,3 [ %dr5 + %dr12 ], %db[20]
		ldrqp,5 [ %dr5 + %dr13 ], %db[21]
		addd %dr5, 0x80, %dr5
	}
	{
		ipd 0
		disp %ctpr1, 1f /* prefetch */

		cmpbedb,4 %dr2, 0x180, %pred3

		ldrqp,0 [ %dr4 + %dr10 ], %db[6]
		ldrqp,2 [ %dr4 + %dr11 ], %db[7]
		ldrqp,3 [ %dr4 + %dr12 ], %db[18]
		ldrqp,5 [ %dr4 + %dr13 ], %db[19]
		addd %dr4, 0x80, %dr4
	}
	{
		ipd 1
		disp %ctpr2, 3f /* copy */

		subd,4 %dr14, 0x40, %dr14

		ldrqp,0 [ %dr5 + %dr10 ], %db[4]
		ldrqp,2 [ %dr5 + %dr11 ], %db[5]
		ldrqp,3 [ %dr5 + %dr12 ], %db[16]
		ldrqp,5 [ %dr5 + %dr13 ], %db[17]
		addd %dr5, 0x80, %dr5
	}
	{
		/* pred0 = not enough data for 2 prefetch iterations =
		 *       = left_to_prefetch <= 0x3c0 =
		 *       = dr1 + dr2 - db[0] <= 0x3c0 =
		 *       = dr1 + dr2 - (dr1 + 0x1a0) <= 0x3c0 =
		 *       = dr2 <= 0x560 */
		cmpbedb,4 %dr2, 0x560, %pred0

		addd,1 %dr1, 0x2a0, %db[1]

		ldrqp,0 [ %dr4 + %dr10 ], %db[2]
		ldrqp,2 [ %dr4 + %dr11 ], %db[3]
		ldrqp,3 [ %dr4 + %dr12 ], %db[14]
		ldrqp,5 [ %dr4 + %dr13 ], %db[15]

		ct %ctpr3 ? %pred15
	}

	/* Load the src block into the L2 cache - prefetching to L1
	 * is neither practical (only 1 line is fetched per cycle)
	 * nor needed (this loop is unrolled enough to do not worry
	 * about latency). */
	{
		subd,4 %dr3, 0x5c0, %dr4
		ldb,sm [ %dr1 + 0x160 ] MAS_BYPASS_L1_CACHE, %empty ? ~ %pred3
		ldb,sm [ %dr1 + 0x180 ] MAS_BYPASS_L1_CACHE, %empty ? ~ %pred3

		ord,1 %dr16, 0x40, %dr17 ? ~ %pred2
		ord,3 %dr16, 0x80, %dr18 ? ~ %pred2
		ord,5 %dr16, 0xc0, %dr19 ? ~ %pred2

		ct %ctpr3 ? %pred2
	}
1: /* prefetch */
	{
		/* pred1 = not enough data for 3 prefetch iterations =
		 *       = left_to_prefetch <= 0x5c0 =
		 *       = dr1 + dr2 - db[0] <= 0x5c0 =
		 *       = dr3 - 0x5c0 <= db[0] =
		 *       = dr4 <= db[0] */
		cmpbedb,4 %dr4, %db[0], %pred1
		ldrd,0 [ %db[0] + %dr16 ], %empty
		ldrd,2 [ %db[0] + %dr17 ], %empty
		ldrd,3 [ %db[0] + %dr18 ], %empty
		ldrd,5 [ %db[0] + %dr19 ], %empty
		addd %db[0], 0x200, %db[0]
	}
	{
		ldrd,0 [ %db[1] + %dr16 ], %empty
		ldrd,2 [ %db[1] + %dr17 ], %empty
		ldrd,3 [ %db[1] + %dr18 ], %empty
		ldrd,5 [ %db[1] + %dr19 ], %empty
		addd %db[1], 0x200, %db[1]
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}

2: /* skip_prefetch_loop */
	/* Copy the page */
	{
		ipd 1
		disp %ctpr1, 4f /* copy_tail */

		ldb,0,sm [ %db[0] + 0 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15
		ldb,2,sm [ %db[0] + 0x40 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15
		ldb,3,sm [ %db[0] + 0x80 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15
		ldb,5,sm [ %db[0] + 0xc0 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15

		cmpbdb,1 %dr2, 0x1c0, %pred0

		/* dr3 = dr1 + dr2 - 0xc0 */
		subd,4 %dr3, 0xc0, %dr3
	}
3: /* copy */
	{
		cmpldb,4 %dr3, %dr5, %pred1

		ldrqp,0 [ %dr5 + %dr10 ], %db[0]
		ldrqp,2 [ %dr5 + %dr11 ], %db[1]
		ldrqp,3 [ %dr5 + %dr12 ], %db[12]
		ldrqp,5 [ %dr5 + %dr13 ], %db[13]
		addd %dr5, 0x40, %dr5
	}
	{
		/* If trap happens on previous instruction %dr14
		 * will be negative, so we check for that in trap
		 * handler. */
		addd,3 %dr14, 0x40, %dr14

		/* Bug 116851 - all strqp must be speculative
		 * if dealing with tags */
		strqp,2,sm [ %dr0 + %dr6 ], %db[10]
		strqp,5,sm [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x40, %dr6
		addd,4 %dr7, 0x40, %dr7
	}
	{
		strqp,2,sm [ %dr0 + %dr8 ], %db[22]
		strqp,5,sm [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x40, %dr8
		addd,4 %dr9, 0x40, %dr9
		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr2 ? ~ %pred0
	}
	/* Copy the remaining tail */
	{
		subd,1 %dr2, 0xc0, %dr3
		ldrqp,0 [ %dr5 + %dr10 ], %db[0] ? ~ %pred6
		ldrqp,2 [ %dr5 + %dr11 ], %db[1] ? ~ %pred6
		addd,3 %dr10, 0x20, %dr10 ? ~ %pred6
		cmpedb 0x0, 0x0, %pred0
		return %ctpr3
	}
	{
		ldrqp,3 [ %dr5 + %dr10 ], %dr13 ? ~ %pred8
	}
4: /* copy_tail */
	{
		addd,3 %dr14, 0x40, %dr14
		cmpbesb %r6, %r3, %pred1
		strqp,2,sm [ %dr0 + %dr6 ], %db[10]
		strqp,5,sm [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x40, %dr6
		addd,4 %dr7, 0x40, %dr7
	}
	{
		strqp,2,sm [ %dr0 + %dr8 ], %db[22]
		strqp,5,sm [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x40, %dr8
		addd,4 %dr9, 0x40, %dr9
		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? %pred0
	}
	{
		addd,3 %dr14, 0x40, %dr14
		strqp,2,sm [ %dr0 + %dr6 ], %db[10] ? ~ %pred6
		strqp,5,sm [ %dr0 + %dr7 ], %db[11] ? ~ %pred6
		addd,1 %dr6, 0x20, %dr6 ? ~ %pred6
	}
	{
		addd,3 %dr14, 0x20, %dr14 ? ~ %pred6
		strqp,sm [ %dr0 + %dr6 ], %dr13 ? ~ %pred8
	}
	{
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}


5: /* very_small_size */
	{
		strqp,sm [ %dr0 + %dr6 ], %db[10] ? ~ %pred26
		strqp,sm [ %dr0 + %dr7 ], %db[11] ? ~ %pred27
	}
	{
		addd,0 %dr14, 0x20, %dr14 ? ~ %pred27
		strqp,sm [ %dr0 + %dr8 ], %db[22] ? ~ %pred28
		strqp,sm [ %dr0 + %dr9 ], %db[23] ? ~ %pred29
	}
	{
		/* Return should not be in the same instruction
		 * with memory access, otherwise we will return
		 * on page fault and page fault handler will
		 * return from our caller. */
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}


6: /* small_size */
	{
		ipd 0
		disp %ctpr1, 7f /* copy_small */

		cmpbdb %dr2, 0xc0, %pred0
		subd,4 %dr3, 0xc0, %dr3

		subd,3 %dr14, 0x40, %dr14 ? ~ %pred12

		ct %ctpr2 ? %pred12
	}
7: /* copy_small */
	{
		cmpldb,4 %dr3, %dr5, %pred1

		ldrqp,0 [ %dr5 + %dr10 ], %db[8]
		ldrqp,3 [ %dr5 + %dr11 ], %db[9]
		ldrqp,2 [ %dr5 + %dr12 ], %db[20]
		ldrqp,5 [ %dr5 + %dr13 ], %db[21]
		addd %dr5, 0x40, %dr5
	}
	{
		/* If trap happens on previous instruction %dr14
		 * will be negative, so we check for that in trap
		 * handler. */
		addd,3 %dr14, 0x40, %dr14

		strqp,2,sm [ %dr0 + %dr6 ], %db[10]
		strqp,5,sm [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x40, %dr6
		addd,4 %dr7, 0x40, %dr7
	}
	{
		strqp,2,sm [ %dr0 + %dr8 ], %db[22]
		strqp,5,sm [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x40, %dr8
		addd,4 %dr9, 0x40, %dr9

		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}
8: /* copy_tail_small */
	{
		addd,4 %dr14, 0x40, %dr14 ? ~ %pred12

		ldrqp,0 [ %dr5 + %dr10 ], %db[8] ? ~ %pred6
		ldrqp,3 [ %dr5 + %dr11 ], %db[9] ? ~ %pred6
		addd,1 %dr10, 0x20, %dr10 ? ~ %pred6
	}
	{
		ldrqp,2 [ %dr5 + %dr10 ], %dr13 ? ~ %pred8
	}
	{
		strqp,2,sm [ %dr0 + %dr6 ], %db[10]
		strqp,5,sm [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x40, %dr6
		addd,4 %dr7, 0x40, %dr7
	}
	{
		addd,3 %dr14, 0x20, %dr14
		strqp,2,sm [ %dr0 + %dr8 ], %db[22]
		strqp,5,sm [ %dr0 + %dr9 ], %db[23]
	}
	{
		addd,3 %dr14, 0x20, %dr14
		strqp,2,sm [ %dr0 + %dr6 ], %db[8] ? ~ %pred6
		strqp,5,sm [ %dr0 + %dr7 ], %db[9] ? ~ %pred6
		addd,1 %dr6, 0x20, %dr6 ? ~ %pred6
	}
	{
		addd,3 %dr14, 0x20, %dr14 ? ~ %pred6
		strqp,2,sm [ %dr0 + %dr6 ], %dr13 ? ~ %pred8
	}
	{
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}
.size $__recovery_memcpy_16, . - $__recovery_memcpy_16

.global $__recovery_memset_16
.type __recovery_memset_16,@function
$__recovery_memset_16:
.ignore ld_st_style
/*
 * dr0 - dst
 * dr1 - value
 * dr2 - tag
 * dr3 - size
 * dr4 - strqp opcode
 */
	{
		setwd wsz = 0x5, nfx = 0
		setbp psz = 0x1

		qppackdl,sm,1 %dr1, %dr1, %dr1

		ipd 0
		disp %ctpr2, 2f /* store_tail */
	}
	{
		ipd 0
		disp %ctpr1, 1f /* store */

		cmpbesb,0 %r3, 0x30, %pred4
		cmpandesb,1 %r3, 0x20, %pred2

		/* dr9 holds the number of cleared bytes in case
		 * pagefault happens. */
		subd,3 0x0, 0x40, %dr9
	}
	{
		return %ctpr3

		cmpbsb,0 %r3, 0x80, %pred0
	}
	{
		cmpandesb,1 %r3, 0x10, %pred3

		subs,0 %r3, 0xc0, %r3

		addd,5 %dr4, 0x10, %dr5
	}
	{
		addd,0 %dr4, 0x20, %dr6
		addd,4 %dr4, 0x30, %dr7

		puttagqp,1 %dr1, %dr2, %dr1

		ct %ctpr2 ? %pred4
	}

1: /* store */
	{
		cmplsb %r3, %r4, %pred1
		strqp,2,sm [ %dr0 + %dr4 ], %dr1
		strqp,5,sm [ %dr0 + %dr5 ], %dr1
		addd,1 %dr4, 0x40, %dr4
		addd,4 %dr5, 0x40, %dr5
		addd,3 %dr9, 0x40, %dr9
	}
	{
		strqp,2,sm [ %dr0 + %dr6 ], %dr1
		strqp,5,sm [ %dr0 + %dr7 ], %dr1
		addd,1 %dr6, 0x40, %dr6
		addd,4 %dr7, 0x40, %dr7
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}

2: /* store_tail */
	{
		strqp,2,sm [ %dr0 + %dr4 ], %dr1 ? ~ %pred2
		strqp,5,sm [ %dr0 + %dr5 ], %dr1 ? ~ %pred2
		addd,3 %dr9, 0x40, %dr9
		addd,1 %dr4, 0x20, %dr4 ? ~ %pred2
	}
	{
		strqp,2,sm [ %dr0 + %dr4 ], %dr1 ? ~ %pred3
		addd,3 %dr9, 0x20, %dr9 ? ~ %pred2
	}
	{
		addd,3 %dr9, 0x10, %dr0 ? ~ %pred3
		addd,4 %dr9, 0, %dr0 ? %pred3
		ct %ctpr3
	}
.size $__recovery_memset_16, . - $__recovery_memset_16
