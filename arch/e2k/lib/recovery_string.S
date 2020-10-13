#include <asm/e2k_api.h>

.section ".text", "ax"
.global $recovery_memcpy_8
.type recovery_memcpy_8,@function
$recovery_memcpy_8:
.ignore ld_st_style
/*
 * dr0 - dst
 * dr1 - src
 * dr2 - len
 * dr3 - strd opcode
 * dr4 - ldrd opcode
 * r5 - enable prefetching
 *
 * Does not return a value.
 */
	{
		setwd wsz = 0x14, nfx = 0x1
		ipd 1
		disp %ctpr2, very_small_size

		setbn rsz = 0xb, rbs = 0x8, rcur = 0x0
		setbp psz = 0x1

		/* dr14 holds the number of copied bytes
		 * in case pagefault happens */
		addd,4 0x0, 0x0, %dr14

		addd,3 %dr4, 0x0, %dr10
		addd,5 %dr4, 0x8, %dr11
	}
	{
		ipd 1
		disp %ctpr1, small_size

		addd,5 %dr4, 0x10, %dr12

		/* %pred26 == 'true' if 'size' is zero (i.e. 'size' >= 8) */
		cmpedb,0 %dr2, 0x0, %pred26
		/* %pred27 == 'false' if 'size' >= 16 bytes */
		cmpbdb,1 %dr2, 0x10, %pred27

		/* %pred28 == 'false' if 'size' >= 24 bytes */
		cmpbdb,3 %dr2, 0x18, %pred28
		/* %pred25 == 'true' if 'size' <= 32 bytes */
		cmpledb,4 %dr2, 0x20, %pred25
	}
	{
		return %ctpr3

		addd,5 %dr4, 0x18, %dr13

		cmpbdb,0 %dr2, 0x40, %pred12
		/* %pred29 == 'false' if 'size' >= 32 bytes */
		cmpbdb,1 %dr2, 0x20, %pred29

		/* If %pred6 is 'false' then the remaining 16-bytes
		 * tail has to be copied after the main copying loop
		 * which copies data in 32-bytes blocks. */
		cmpandedb,3 %dr2, 0x10, %pred6
		/* %pred7 == 'size' < 192 (minimum allowed size
		 * for the optimized copying algorythm - 6 cachelines
		 * for unrolling) */
		cmpbdb,4 %dr2, 0xc0, %pred7
	}
	{
		/* %pred8 == 'true' if 'size' is a multiple of 16 */
		cmpandedb,1 %dr2, 0x8, %pred8

		addd,0 %dr3, 0x0, %dr6
		addd,2 %dr3, 0x10, %dr8

		addd,4 %dr3, 0x8, %dr7

		ldrd,3 [ %dr1 + %dr10 ], %db[10] ? ~ %pred26
		ldrd,5 [ %dr1 + %dr11 ], %db[11] ? ~ %pred27
	}
	{
		addd,4 %dr3, 0x18, %dr9

		ldrd,3 [ %dr1 + %dr12 ], %db[22] ? ~ %pred28
		ldrd,5 [ %dr1 + %dr13 ], %db[23] ? ~ %pred29

		ct %ctpr2 ? %pred25
	}
	{
		ipd 0
		disp %ctpr2, copy_tail_small

		addd,1 %dr1, 0x100, %db[0]

		/* Check whether prefetching is disabled */
		cmpesb,4 %r5, 0, %pred15

		addd,0 %dr1, 0x20, %dr5
		addd,2 %dr1, 0x40, %dr4

		addd,5 %dr1, %dr2, %dr3

		/* If the block is small, use simple loop without unrolling */
		ct %ctpr1 ? %pred7
	}
	{
		ipd 0
		disp %ctpr3, skip_prefetch_loop

		cmpbdb,4 %dr2, 0x2c0, %pred2

		ldrd,0 [ %dr5 + %dr10 ], %db[8]
		ldrd,2 [ %dr5 + %dr11 ], %db[9]
		ldrd,3 [ %dr5 + %dr12 ], %db[20]
		ldrd,5 [ %dr5 + %dr13 ], %db[21]
		addd %dr5, 0x40, %dr5
	}
	{
		ipd 0
		disp %ctpr1, prefetch

		cmpbdb,4 %dr2, 0xe0, %pred3

		ldrd,0 [ %dr4 + %dr10 ], %db[6]
		ldrd,2 [ %dr4 + %dr11 ], %db[7]
		ldrd,3 [ %dr4 + %dr12 ], %db[18]
		ldrd,5 [ %dr4 + %dr13 ], %db[19]
		addd %dr4, 0x40, %dr4
	}
	{
		ipd 1
		disp %ctpr2, copy

		ldrd,0 [ %dr5 + %dr10 ], %db[4]
		ldrd,2 [ %dr5 + %dr11 ], %db[5]
		ldrd,3 [ %dr5 + %dr12 ], %db[16]
		ldrd,5 [ %dr5 + %dr13 ], %db[17]
		addd %dr5, 0x40, %dr5
	}
	{
		cmpbdb,4 %dr2, 0x4c0, %pred0

		addd,1 %dr1, 0x100, %db[1]

		ldrd,0 [ %dr4 + %dr10 ], %db[2]
		ldrd,2 [ %dr4 + %dr11 ], %db[3]
		ldrd,3 [ %dr4 + %dr12 ], %db[14]
		ldrd,5 [ %dr4 + %dr13 ], %db[15]

		ct %ctpr3 ? %pred15
	}

	/* Load the src block into the L2 cache - prefetching to L1
	 * is neither practical (only 1 line is fetched per cycle)
	 * nor needed (this loop is unrolled enough to do not worry
	 * about latency). */
	{
		subd,4 %dr3, 0x5c0, %dr4
		ldb,sm [ %dr1 + 0xc0 ] MAS_BYPASS_L1_CACHE, %empty ? ~ %pred3
		ldb,sm [ %dr1 + 0xe0 ] MAS_BYPASS_L1_CACHE, %empty ? ~ %pred3

		ct %ctpr3 ? %pred2
	}
prefetch:
	{
		/* pred1 = dr4 < db[0] =
		 *       = dr1 + dr2 - 0x5c0 < dr1 + prefetched =
		 *       = dr2 - prefetched < 0x5c0 =
		 *       = size - prefetched < 0x5c0 */
		cmpbdb,4 %dr4, %db[0], %pred1
		ldb,0,sm [ %db[0] + 0 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,2,sm [ %db[0] + 0x40 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,3,sm [ %db[0] + 0x80 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,5,sm [ %db[0] + 0xc0 ] MAS_BYPASS_L1_CACHE, %empty
		addd %db[0], 0x200, %db[0]
	}
	{
		ldb,0,sm [ %db[1] + 0x100 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,2,sm [ %db[1] + 0x140 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,3,sm [ %db[1] + 0x180 ] MAS_BYPASS_L1_CACHE, %empty
		ldb,5,sm [ %db[1] + 0x1c0 ] MAS_BYPASS_L1_CACHE, %empty
		addd %db[1], 0x200, %db[1]
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}

skip_prefetch_loop:
	/* Copy the page */
	{
		ipd 1
		disp %ctpr1, copy_tail

		subd,5 %dr14, 0x20, %dr14

		ldb,0,sm [ %db[0] + 0 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15
		ldb,2,sm [ %db[0] + 0x40 ] (MAS_LOAD_SPEC | MAS_BYPASS_L1_CACHE), %empty ? ~ %pred15

		cmpbdb,3 %dr2, 0xe0, %pred0

		/* dr3 = dr1 + dr2 - 0x60 */
		subd,4 %dr3, 0x60, %dr3
	}
copy:
	{
		cmpldb,4 %dr3, %dr5, %pred1

		ldrd,0 [ %dr5 + %dr10 ], %db[0]
		ldrd,2 [ %dr5 + %dr11 ], %db[1]
		ldrd,3 [ %dr5 + %dr12 ], %db[12]
		ldrd,5 [ %dr5 + %dr13 ], %db[13]
		addd %dr5, 0x20, %dr5
	}
	{
		/* If trap happens on previous instruction %dr14
		 * will be negative, so we check for that in trap
		 * handler. */
		addd,3 %dr14, 0x20, %dr14

		strd,2 [ %dr0 + %dr6 ], %db[10]
		strd,5 [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x20, %dr6
		addd,4 %dr7, 0x20, %dr7
	}
	{
		strd,2 [ %dr0 + %dr8 ], %db[22]
		strd,5 [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x20, %dr8
		addd,4 %dr9, 0x20, %dr9
		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr2 ? ~ %pred0
	}
	/* Copy the remaining tail */
	{
		subd,1 %dr2, 0x60, %dr3
		ldrd,0 [ %dr5 + %dr10 ], %db[0] ? ~ %pred6
		ldrd,2 [ %dr5 + %dr11 ], %db[1] ? ~ %pred6
		addd,3 %dr10, 0x10, %dr10 ? ~ %pred6
		cmpedb 0x0, 0x0, %pred0
		return %ctpr3
	}
	{
		ldrd,3 [ %dr5 + %dr10 ], %dr13 ? ~ %pred8
	}
copy_tail:
	{
		addd,3 %dr14, 0x20, %dr14
		cmpbesb %r6, %r3, %pred1
		strd,2 [ %dr0 + %dr6 ], %db[10]
		strd,5 [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x20, %dr6
		addd,4 %dr7, 0x20, %dr7
	}
	{
		strd,2 [ %dr0 + %dr8 ], %db[22]
		strd,5 [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x20, %dr8
		addd,4 %dr9, 0x20, %dr9
		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? %pred0
	}
	{
		addd,3 %dr14, 0x20, %dr14
		strd,2 [ %dr0 + %dr6 ], %db[10] ? ~ %pred6
		strd,5 [ %dr0 + %dr7 ], %db[11] ? ~ %pred6
		addd,1 %dr6, 0x10, %dr6 ? ~ %pred6
	}
	{
		addd,3 %dr14, 0x10, %dr14 ? ~ %pred6
		strd [ %dr0 + %dr6 ], %dr13 ? ~ %pred8
	}
	{
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}


very_small_size:
	{
		strd [ %dr0 + %dr6 ], %db[10] ? ~ %pred26
		strd [ %dr0 + %dr7 ], %db[11] ? ~ %pred27
	}
	{
		addd,0 %dr14, 0x10, %dr14 ? ~ %pred27
		strd [ %dr0 + %dr8 ], %db[22] ? ~ %pred28
		strd [ %dr0 + %dr9 ], %db[23] ? ~ %pred29
	}
	{
		/* Return should not be in the same instruction
		 * with memory access, otherwise we will return
		 * on page fault and page fault handler will
		 * return from our caller. */
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}


small_size:
	{
		ipd 0
		disp %ctpr1, copy_small

		cmpbdb %dr2, 0x60, %pred0
		subd,4 %dr3, 0x60, %dr3

		subd,3 %dr14, 0x20, %dr14 ? ~ %pred12

		ct %ctpr2 ? %pred12
	}
copy_small:
	{
		cmpldb,4 %dr3, %dr5, %pred1

		ldrd,0 [ %dr5 + %dr10 ], %db[8]
		ldrd,3 [ %dr5 + %dr11 ], %db[9]
		ldrd,2 [ %dr5 + %dr12 ], %db[20]
		ldrd,5 [ %dr5 + %dr13 ], %db[21]
		addd %dr5, 0x20, %dr5
	}
	{
		/* If trap happens on previous instruction %dr14
		 * will be negative, so we check for that in trap
		 * handler. */
		addd,3 %dr14, 0x20, %dr14

		strd,2 [ %dr0 + %dr6 ], %db[10]
		strd,5 [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x20, %dr6
		addd,4 %dr7, 0x20, %dr7
	}
	{
		strd,2 [ %dr0 + %dr8 ], %db[22]
		strd,5 [ %dr0 + %dr9 ], %db[23]
		addd,1 %dr8, 0x20, %dr8
		addd,4 %dr9, 0x20, %dr9

		abn abnf = 1, abnt = 1
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}
copy_tail_small:
	{
		addd,4 %dr14, 0x20, %dr14 ? ~ %pred12

		ldrd,0 [ %dr5 + %dr10 ], %db[8] ? ~ %pred6
		ldrd,3 [ %dr5 + %dr11 ], %db[9] ? ~ %pred6
		addd,1 %dr10, 0x10, %dr10 ? ~ %pred6
	}
	{
		ldrd,2 [ %dr5 + %dr10 ], %dr13 ? ~ %pred8
	}
	{
		strd,2 [ %dr0 + %dr6 ], %db[10]
		strd,5 [ %dr0 + %dr7 ], %db[11]
		addd,1 %dr6, 0x20, %dr6
		addd,4 %dr7, 0x20, %dr7
	}
	{
		addd,3 %dr14, 0x10, %dr14
		strd,2 [ %dr0 + %dr8 ], %db[22]
		strd,5 [ %dr0 + %dr9 ], %db[23]
	}
	{
		addd,3 %dr14, 0x10, %dr14
		strd,2 [ %dr0 + %dr6 ], %db[8] ? ~ %pred6
		strd,5 [ %dr0 + %dr7 ], %db[9] ? ~ %pred6
		addd,1 %dr6, 0x10, %dr6 ? ~ %pred6
	}
	{
		addd,3 %dr14, 0x10, %dr14 ? ~ %pred6
		strd,2 [ %dr0 + %dr6 ], %dr13 ? ~ %pred8
	}
	{
		addd,3 %dr2, 0x0, %dr0
		ct %ctpr3
	}
.size $recovery_memcpy_8, . - $recovery_memcpy_8

.global $recovery_memcpy_fault
.global $.recovery_memcpy_fault
$recovery_memcpy_fault:
$.recovery_memcpy_fault:
.ignore ld_st_style
	{
		nop
		cmpldb %dr14, 0, %pred0
		return %ctpr3
	}
	{
		addd 0, 0, %dr0 ? %pred0
		addd 0, %dr14, %dr0 ? ~ %pred0
		ct %ctpr3
	}
.size $recovery_memcpy_fault, . - $recovery_memcpy_fault

.global $recovery_memset_8
$recovery_memset_8:
.ignore ld_st_style
/*
 * dr0 - dst
 * dr1 - value
 * dr2 - tag
 * dr3 - size
 * dr4 - strd opcode
 */
	{
		ipd 0
		disp %ctpr2, store_tail

		setbp psz = 0x1
	}
	{
		ipd 0
		disp %ctpr1, store

		cmpbesb,0 %r3, 0x18, %pred4
		cmpandesb,1 %r3, 0x10, %pred2

		puttagd,2 %dr1, %dr2, %dr1
	}
	{
		return %ctpr3

		cmpbsb,0 %r3, 0x40, %pred0
		cmpandesb,1 %r3, 0x8, %pred3
	}
	{
		subs,1 %r3, 0x60, %r3

		addd,5 %dr4, 0x8, %dr5
	}
	{
		addd,1 %dr4, 0x10, %dr6
		addd,4 %dr4, 0x18, %dr7

		ct %ctpr2 ? %pred4
	}

store:
	{
		cmplsb %r3, %r4, %pred1
		strd,2 [ %dr0 + %dr4 ], %dr1
		strd,5 [ %dr0 + %dr5 ], %dr1
		addd,1 %dr4, 0x20, %dr4
		addd,4 %dr5, 0x20, %dr5
	}
	{
		strd,2 [ %dr0 + %dr6 ], %dr1
		strd,5 [ %dr0 + %dr7 ], %dr1
		addd,1 %dr6, 0x20, %dr6
		addd,4 %dr7, 0x20, %dr7
		abp abpf = 1, abpt = 1
		ct %ctpr1 ? ~ %pred0
	}

store_tail:
	{
		strd,2 [ %dr0 + %dr4 ], %dr1 ? ~ %pred2
		strd,5 [ %dr0 + %dr5 ], %dr1 ? ~ %pred2
		addd,1 %dr4, 0x10, %dr4 ? ~ %pred2
	}
	{
		strd,2 [ %dr0 + %dr4 ], %dr1 ? ~ %pred3
		ct %ctpr3
	}
.size $recovery_memset_8, . - $recovery_memset_8
