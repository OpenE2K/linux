/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/const.h>
#include <linux/types.h>

/* <uapi/asm/mas.h> is deprecated and left for compatibility only,
 * do not include it here */


typedef union e2k_mas {
	struct {
		u8 mod	: 3; /* mod == 7 */
		u8 opc	: 4;
		u8	: 1;
	} masf1;
	struct {
		u8 mod	 : 3; /* mod == 0 - 7 */
		u8 be    : 1;
		u8 m1	 : 1 /* m1 == 0 */;
		u8 dc_ch : 2;
		u8       : 1;
	} masf2;
	struct {
		u8 mod : 3 /* == 3,7 */;
		u8 be  : 1;
		u8 m1  : 1 /* m1 == 1 */;
		u8 m3  : 1;
		u8 mt  : 1;
		u8     : 1;
	} masf3;
	struct {
		struct {
			u8 m2    : 2;   /* {ch1,m2} == mod */
			u8 ch1   : 1;   /* mod = 0,1,2,4,5,6 */
			u8 be    : 1;
			u8 m1	 : 1 /* m1 == 1 */;
			u8 dc_ch : 2;
			u8       : 1;
		} masf4;
	} v6; /* Introduced in iset v6 */
	u8 word;
} e2k_mas_t;

#define	MAS_ENDIAN_MASK		0x08

#define MAS_MT_0		ULL(0)
#define MAS_MT_1		ULL(1)

/* Note that accesses by physical address always bypass L1 cache */
#define CACHE_BYPASS_NONE	ULL(0)
#define CACHE_BYPASS_L1		ULL(1)
#define CACHE_BYPASS_L12	ULL(2)
#define CACHE_BYPASS_ALL	ULL(3)

#define MAS_BYPASS_NONE		MAS_NORMAL(CACHE_BYPASS_NONE, 0)
#define MAS_BYPASS_L1_CACHE	MAS_NORMAL(CACHE_BYPASS_L1, 0)
#define MAS_BYPASS_L12_CACHES	MAS_NORMAL(CACHE_BYPASS_L12, 0)
#define MAS_BYPASS_ALL_CACHES	MAS_NORMAL(CACHE_BYPASS_ALL, 0)

#define MAS_DISABLED_TRANSLATION_BYPASS(_dc) ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 1, \
	.masf2.dc_ch = (_dc),\
}).word

#define MAS_DISABLED_TRANSLATION MAS_DISABLED_TRANSLATION_BYPASS(CACHE_BYPASS_NONE)

#define MAS_FILL_OPERATION(_dc, _be) ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 4, \
	.masf2.dc_ch = (_dc),\
	.masf2.be = (_be), \
}).word

#define MAS_IO_OPERATION ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 6, \
}).word

#define MAS_LOAD_ACQUIRE_V6(_mt) ((e2k_mas_t) { \
	.masf3.mod = 3, \
	.masf3.m1 = 1, \
	.masf3.m3 = 0, \
	.masf3.mt = (_mt) \
}).word

#define MAS_SPECULATIVE(_dc) ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 3, \
	.masf2.dc_ch = (_dc),\
}).word

#define MAS_LOCK_CHECK(_dc) ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 4, \
	.masf2.dc_ch = (_dc), \
}).word

#define MAS_LOCK_WAIT ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 7, \
}).word

#define MAS_NORMAL(_dc, _be) ((e2k_mas_t) { \
	.masf2.m1 = 0, \
	.masf2.mod = 0, \
	.masf2.dc_ch = (_dc), \
	.masf2.be = (_be), \
}).word

#define MAS_SPECIAL_MMU_AAU(_opc) ((e2k_mas_t) { \
	.masf1.mod = 7, \
	.masf1.opc = (_opc), \
}).word

#define MAS_STORE_RELEASE_V6(_mt) ((e2k_mas_t) { \
	.masf3.mod = 3, \
	.masf3.m1 = 1, \
	.masf3.m3 = 0, \
	.masf3.mt = (_mt) \
}).word

/* Only ALC0 or ALC0/ALC2 for quadro */
#define MAS_WATCH_FOR_MODIFICATION_V6 ((e2k_mas_t) { \
	.v6.masf4.m1 = 1, \
	.v6.masf4.m2 = 1, \
}).word


/*
 * Special MMU/AAU operations
 */

#define	MAS_OPC_CACHE_FLUSH		0UL
#define	MAS_OPC_CACHE_LINE_FLUSH	1UL
#define	MAS_OPC_ICACHE_LINE_FLUSH	2UL
#define	MAS_OPC_TLB_PAGE_FLUSH		2UL
#define	MAS_OPC_MEMORY_LOCKS_INVALIDATE	3UL
#define	MAS_OPC_ICACHE_FLUSH		4UL
#define	MAS_OPC_TLB_FLUSH		4UL
#define	MAS_OPC_TLB_ENTRY_PROBE		6UL
#define	MAS_OPC_AAU_REG			7UL
#define	MAS_OPC_MMU_REG			8UL
#define	MAS_OPC_DTLB_REG		9UL
#define	MAS_OPC_L1_REG			10UL
#define	MAS_OPC_L2_REG			11UL
#define	MAS_OPC_ICACHE_REG		12UL
#define	MAS_OPC_SNOOP_REG		13UL
#define	MAS_OPC_DAM_REG			13UL
#define	MAS_OPC_MLT_REG			13UL
#define	MAS_OPC_CLW_REG			13UL
#define	MAS_OPC_MMU_DEBUG_REG		13UL

#define MAS_CACHE_FLUSH		MAS_SPECIAL_MMU_AAU(MAS_OPC_CACHE_FLUSH)
#define MAS_CACHE_LINE_FLUSH	MAS_SPECIAL_MMU_AAU(MAS_OPC_CACHE_LINE_FLUSH)
#define MAS_ICACHE_LINE_FLUSH	MAS_SPECIAL_MMU_AAU(MAS_OPC_ICACHE_LINE_FLUSH)
#define MAS_TLB_PAGE_FLUSH	MAS_SPECIAL_MMU_AAU(MAS_OPC_TLB_PAGE_FLUSH)
#define MAS_ICACHE_FLUSH	MAS_SPECIAL_MMU_AAU(MAS_OPC_ICACHE_FLUSH)
#define MAS_TLB_FLUSH		MAS_SPECIAL_MMU_AAU(MAS_OPC_TLB_FLUSH)
#define MAS_TLB_ENTRY_PROBE	MAS_SPECIAL_MMU_AAU(MAS_OPC_TLB_ENTRY_PROBE)
#define MAS_MMU_REG		MAS_SPECIAL_MMU_AAU(MAS_OPC_MMU_REG)
#define MAS_DTLB_REG		MAS_SPECIAL_MMU_AAU(MAS_OPC_DTLB_REG)
#define MAS_DCACHE_L1_REG	MAS_SPECIAL_MMU_AAU(MAS_OPC_L1_REG)
#define MAS_DCACHE_L2_REG	MAS_SPECIAL_MMU_AAU(MAS_OPC_L2_REG)
#define MAS_DAM_REG		MAS_SPECIAL_MMU_AAU(MAS_OPC_DAM_REG)
#define MAS_MLT_REG		MAS_SPECIAL_MMU_AAU(MAS_OPC_MLT_REG)
#define MAS_CLW_REG		MAS_SPECIAL_MMU_AAU(MAS_OPC_CLW_REG)
#define MAS_MMU_DEBUG_REG	MAS_SPECIAL_MMU_AAU(MAS_OPC_MMU_DEBUG_REG)
