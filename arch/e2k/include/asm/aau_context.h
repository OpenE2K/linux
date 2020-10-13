/*
 * aau_context.h - saving/loading AAU context.
 *
 * In this file you can see various lists of similar operations. All
 * of these operations are of AAU access. The hint is the following:
 * AAU regiters can be obtained only through LDAA operation with index
 * hardcoded into the AAU syllable. So, index as variable can not be
 * substituted. As a cosequence we can not pack them into the loop and
 * they are forced to be in lists.
 */
#ifndef _E2K_AAU_CONTEXT_H_
#define _E2K_AAU_CONTEXT_H_

#include <asm/aau_regs.h>
#include <asm/byteorder.h>
#include <asm/uaccess.h>
#include <asm/e2k_syswork.h>

/******************************* DEBUG DEFINES ********************************/
#undef	DEBUG_AAU_CHECK

#define DEBUG_AAU_CHECK		0
#define DbgChk	if (DEBUG_AAU_CHECK) printk
/******************************************************************************/

typedef union e2k_fapb_aps {
	union {
		struct {
			u64 abs  : 5;   /* [4:0] area base */
			u64 asz  : 3;   /* [7:5] area size */
			u64 ind  : 4;   /* [11:8] initial index (si == 0) */
			u64 incr : 3;   /* [14:12] AAINCR number (si == 0) */
			u64 d    : 5;   /* [19:15] AAD number */
			u64 mrng : 5;   /* [24:20] element size */
			u64 fmt  : 3;   /* [27:25] format */
			u64 dcd  : 2;   /* [29:28] data cache disabled */
			u64 si   : 1;   /* [30] secondary index access */
			u64 ct   : 1;   /* [31] control transfer (left ch.) */
			u64 disp : 32;
		};
		struct {
			u64 __x1 : 8;
			u64 area : 5;   /* [12:8] APB area index (si == 1) */
			u64 am   : 1;   /* [13] (si == 1) */
			u64 be   : 1;   /* [14] big endian (si == 1) */
			u64 __x2 : 16;
			u64 dpl  : 1;   /* [31] duplicate (right channel) */
			u64 __x3 : 32;
		};
	} fields;
	u64 word;
} e2k_fapb_instr_t;

/* constants to pick LSR register fields up */
#define LSR_LCNT_MASK 0xFFFFFFFF
#define LSR_LDMC_MASK 0x1
#define LSR_LDMC_SHIFT 39
#define LSR_ECNT_MASK 0x1f
#define LSR_ECNT_SHIFT 32
#define LSR_PCNT_MASK 0xf
#define LSR_PCNT_SHIFT 48

#define get_lcnt(reg)	(reg & LSR_LCNT_MASK)
#define get_ldmc(reg)	((reg >> LSR_LDMC_SHIFT) & LSR_LDMC_MASK)
#define get_ecnt(reg)	((reg >> LSR_ECNT_SHIFT) & LSR_ECNT_MASK)
#define get_pcnt(reg)	((reg >> LSR_PCNT_SHIFT) & LSR_PCNT_MASK)

static	inline	void
get_array_descriptors(e2k_aau_t *context)
{
	u32 *const aainds = context->aainds;
	u32 *const aaincrs = context->aaincrs;

	/* get AAINDs, omit the AAIND0 saving since it has predefined 0
	 * value
	 */
	{
		register u32    aaind1, aaind2, aaind3, aaind4,
				aaind5, aaind6, aaind7, aaind8,
				aaind9, aaind10, aaind11, aaind12,
				aaind13, aaind14, aaind15, aaind_tags;

		E2K_GET_AAU_AAINDS(aaind1, aaind2, aaind1, aaind2);
		E2K_GET_AAU_AAINDS(aaind3, aaind4, aaind3, aaind4);
		E2K_GET_AAU_AAINDS(aaind5, aaind6, aaind5, aaind6);
		E2K_GET_AAU_AAINDS(aaind7, aaind8, aaind7, aaind8);
		E2K_GET_AAU_AAINDS(aaind9, aaind10, aaind9, aaind10);
		E2K_GET_AAU_AAINDS(aaind11, aaind12, aaind11, aaind12);
		E2K_GET_AAU_AAINDS(aaind13, aaind14, aaind13, aaind14);
		E2K_GET_AAUREGS(aaind15, aaind_tag, aaind15, aaind_tags);

		aainds[0] = 0;
		aainds[1] = aaind1;
		aainds[2] = aaind2;
		aainds[3] = aaind3;
		aainds[4] = aaind4;
		aainds[5] = aaind5;
		aainds[6] = aaind6;
		aainds[7] = aaind7;
		aainds[8] = aaind8;
		aainds[9] = aaind9;
		aainds[10] = aaind10;
		aainds[11] = aaind11;
		aainds[12] = aaind12;
		aainds[13] = aaind13;
		aainds[14] = aaind14;
		aainds[15] = aaind15;
		context->aaind_tags = aaind_tags;
	}

	/* get AAINCRs, omit the AAINCR0 saving since it has predefined 1
	 * value
	 */
	{
		register u32    aaincr1, aaincr2, aaincr3, aaincr4,
				aaincr5, aaincr6, aaincr7, aaincr_tags;

		E2K_GET_AAU_AAINCRS(aaincr1, aaincr2, aaincr1, aaincr2);
		E2K_GET_AAU_AAINCRS(aaincr3, aaincr4, aaincr3, aaincr4);
		E2K_GET_AAU_AAINCRS(aaincr5, aaincr6, aaincr5, aaincr6);
		E2K_GET_AAU_AAINCRS(aaincr7, aaincr_tag, aaincr7, aaincr_tags);

		aaincrs[0] = 1;
		aaincrs[1] = aaincr1;
		aaincrs[2] = aaincr2;
		aaincrs[3] = aaincr3;
		aaincrs[4] = aaincr4;
		aaincrs[5] = aaincr5;
		aaincrs[6] = aaincr6;
		aaincrs[7] = aaincr7;
		context->aaincr_tags = aaincr_tags;
	}
}

static __always_inline void set_array_descriptors(e2k_aau_t *context)
{
	const u32 *const aainds = context->aainds;
	const u32 *const aaincrs = context->aaincrs;

	/* 
	 * set AAINDs, omit the AAIND0 loading since it has predefined 0
	 * value
	 */
	{
		register u32    aaind1 = aainds[1], aaind2 = aainds[2],
				aaind3 = aainds[3], aaind4 = aainds[4],
				aaind5 = aainds[5], aaind6 = aainds[6],
				aaind7 = aainds[7], aaind8 = aainds[8],
				aaind9 = aainds[9], aaind10 = aainds[10],
				aaind11 = aainds[11], aaind12 = aainds[12],
				aaind13 = aainds[13], aaind14 = aainds[14],
				aaind15 = aainds[15],
				aaind_tags = context->aaind_tags;

		E2K_SET_AAU_AAINDS(aaind1, aaind2, aaind1, aaind2);
		E2K_SET_AAU_AAINDS(aaind3, aaind4, aaind3, aaind4);
		E2K_SET_AAU_AAINDS(aaind5, aaind6, aaind5, aaind6);
		E2K_SET_AAU_AAINDS(aaind7, aaind8, aaind7, aaind8);
		E2K_SET_AAU_AAINDS(aaind9, aaind10, aaind9, aaind10);
		E2K_SET_AAU_AAINDS(aaind11, aaind12, aaind11, aaind12);
		E2K_SET_AAU_AAINDS(aaind13, aaind14, aaind13, aaind14);
		E2K_SET_AAUREGS(aaind15, aaind_tag, aaind15, aaind_tags);
	}

	/*
	 * set AAINCRs, omit the AAINCR0 loading since it has predefined
	 * 1 value
	 */
	{
		register u32    aaincr1 = aaincrs[1], aaincr2 = aaincrs[2],
				aaincr3 = aaincrs[3], aaincr4 = aaincrs[4],
				aaincr5 = aaincrs[5], aaincr6 = aaincrs[6],
				aaincr7 = aaincrs[7],
				aaincr_tags = context->aaincr_tags;

		E2K_SET_AAU_AAINCRS(aaincr1, aaincr2, aaincr1, aaincr2);
		E2K_SET_AAU_AAINCRS(aaincr3, aaincr4, aaincr3, aaincr4);
		E2K_SET_AAU_AAINCRS(aaincr5, aaincr6, aaincr5, aaincr6);
		E2K_SET_AAUREGS(aaincr7, aaincr_tag, aaincr7, aaincr_tags);
	}
}

static	inline void
get_synchronous_part(e2k_aau_t *context)
{
	u32     *const aastis = context->aastis;
	register u32    aasti0, aasti1, aasti2, aasti3,
			aasti4, aasti5, aasti6, aasti7,
			aasti8, aasti9, aasti10, aasti11,
			aasti12, aasti13, aasti14, aasti15,
			aasti_tags;

	/* get AASTIs */
	E2K_GET_AAU_AASTIS(aasti0, aasti1, aasti0, aasti1);
	E2K_GET_AAU_AASTIS(aasti2, aasti3, aasti2, aasti3);
	E2K_GET_AAU_AASTIS(aasti4, aasti5, aasti4, aasti5);
	E2K_GET_AAU_AASTIS(aasti6, aasti7, aasti6, aasti7);
	E2K_GET_AAU_AASTIS(aasti8, aasti9, aasti8, aasti9);
	E2K_GET_AAU_AASTIS(aasti10, aasti11, aasti10, aasti11);
	E2K_GET_AAU_AASTIS(aasti12, aasti13, aasti12, aasti13);
	E2K_GET_AAU_AASTIS(aasti14, aasti15, aasti14, aasti15);
	aasti_tags = E2K_GET_AAU_AASTI_TAG();

	aastis[0] = aasti0;
	aastis[1] = aasti1;
	aastis[2] = aasti2;
	aastis[3] = aasti3;
	aastis[4] = aasti4;
	aastis[5] = aasti5;
	aastis[6] = aasti6;
	aastis[7] = aasti7;
	aastis[8] = aasti8;
	aastis[9] = aasti9;
	aastis[10] = aasti10;
	aastis[11] = aasti11;
	aastis[12] = aasti12;
	aastis[13] = aasti13;
	aastis[14] = aasti14;
	aastis[15] = aasti15;
	context->aasti_tags = aasti_tags;
}

static __always_inline void set_synchronous_part(e2k_aau_t *context)
{
	const u32 *const aastis = context->aastis;
	register u32    aasti0 = aastis[0], aasti1 = aastis[1],
			aasti2 = aastis[2], aasti3 = aastis[3],
			aasti4 = aastis[4], aasti5 = aastis[5],
			aasti6 = aastis[6], aasti7 = aastis[7],
			aasti8 = aastis[8], aasti9 = aastis[9],
			aasti10 = aastis[10], aasti11 = aastis[11],
			aasti12 = aastis[12], aasti13 = aastis[13],
			aasti14 = aastis[14], aasti15 = aastis[15],
			aasti_tags = context->aasti_tags;

	/* set AASTIs */
	E2K_SET_AAU_AASTIS(aasti0, aasti1, aasti0, aasti1);
	E2K_SET_AAU_AASTIS(aasti2, aasti3, aasti2, aasti3);
	E2K_SET_AAU_AASTIS(aasti4, aasti5, aasti4, aasti5);
	E2K_SET_AAU_AASTIS(aasti6, aasti7, aasti6, aasti7);
	E2K_SET_AAU_AASTIS(aasti8, aasti9, aasti8, aasti9);
	E2K_SET_AAU_AASTIS(aasti10, aasti11, aasti10, aasti11);
	E2K_SET_AAU_AASTIS(aasti12, aasti13, aasti12, aasti13);
	E2K_SET_AAU_AASTIS(aasti14, aasti15, aasti14, aasti15);

	E2K_SET_AAU_AASTI_TAG(aasti_tags);
}

static inline void
set_all_aaldis(const u32 aaldis[])
{
	{
		register u32    aaldi0 = aaldis[0], aaldi32 = aaldis[32],
				aaldi1 = aaldis[1], aaldi33 = aaldis[33],
				aaldi2 = aaldis[2], aaldi34 = aaldis[34],
				aaldi3 = aaldis[3], aaldi35 = aaldis[35],
				aaldi4 = aaldis[4], aaldi36 = aaldis[36],
				aaldi5 = aaldis[5], aaldi37 = aaldis[37],
				aaldi6 = aaldis[6], aaldi38 = aaldis[38],
				aaldi7 = aaldis[7], aaldi39 = aaldis[39];
		E2K_SET_AAU_AALDI(aaldi0,  aaldi0, aaldi32);
		E2K_SET_AAU_AALDI(aaldi1,  aaldi1, aaldi33);
		E2K_SET_AAU_AALDI(aaldi2,  aaldi2, aaldi34);
		E2K_SET_AAU_AALDI(aaldi3,  aaldi3, aaldi35);
		E2K_SET_AAU_AALDI(aaldi4,  aaldi4, aaldi36);
		E2K_SET_AAU_AALDI(aaldi5,  aaldi5, aaldi37);
		E2K_SET_AAU_AALDI(aaldi6,  aaldi6, aaldi38);
		E2K_SET_AAU_AALDI(aaldi7,  aaldi7, aaldi39);
	}
	{
		register u32    aaldi8  = aaldis[8],  aaldi40 = aaldis[40],
				aaldi9  = aaldis[9],  aaldi41 = aaldis[41],
				aaldi10 = aaldis[10], aaldi42 = aaldis[42],
				aaldi11 = aaldis[11], aaldi43 = aaldis[43],
				aaldi12 = aaldis[12], aaldi44 = aaldis[44],
				aaldi13 = aaldis[13], aaldi45 = aaldis[45],
				aaldi14 = aaldis[14], aaldi46 = aaldis[46],
				aaldi15 = aaldis[15], aaldi47 = aaldis[47];
		E2K_SET_AAU_AALDI(aaldi8,  aaldi8, aaldi40);
		E2K_SET_AAU_AALDI(aaldi9,  aaldi9, aaldi41);
		E2K_SET_AAU_AALDI(aaldi10, aaldi10, aaldi42);
		E2K_SET_AAU_AALDI(aaldi11, aaldi11, aaldi43);
		E2K_SET_AAU_AALDI(aaldi12, aaldi12, aaldi44);
		E2K_SET_AAU_AALDI(aaldi13, aaldi13, aaldi45);
		E2K_SET_AAU_AALDI(aaldi14, aaldi14, aaldi46);
		E2K_SET_AAU_AALDI(aaldi15, aaldi15, aaldi47);
	}
	{
		register u32    aaldi16 = aaldis[16], aaldi48 = aaldis[48],
				aaldi17 = aaldis[17], aaldi49 = aaldis[49],
				aaldi18 = aaldis[18], aaldi50 = aaldis[50],
				aaldi19 = aaldis[19], aaldi51 = aaldis[51],
				aaldi20 = aaldis[20], aaldi52 = aaldis[52],
				aaldi21 = aaldis[21], aaldi53 = aaldis[53],
				aaldi22 = aaldis[22], aaldi54 = aaldis[54],
				aaldi23 = aaldis[23], aaldi55 = aaldis[55];
		E2K_SET_AAU_AALDI(aaldi16, aaldi16, aaldi48);
		E2K_SET_AAU_AALDI(aaldi17, aaldi17, aaldi49);
		E2K_SET_AAU_AALDI(aaldi18, aaldi18, aaldi50);
		E2K_SET_AAU_AALDI(aaldi19, aaldi19, aaldi51);
		E2K_SET_AAU_AALDI(aaldi20, aaldi20, aaldi52);
		E2K_SET_AAU_AALDI(aaldi21, aaldi21, aaldi53);
		E2K_SET_AAU_AALDI(aaldi22, aaldi22, aaldi54);
		E2K_SET_AAU_AALDI(aaldi23, aaldi23, aaldi55);
	}
	{
		register u32    aaldi24 = aaldis[24], aaldi56 = aaldis[56],
				aaldi25 = aaldis[25], aaldi57 = aaldis[57],
				aaldi26 = aaldis[26], aaldi58 = aaldis[58],
				aaldi27 = aaldis[27], aaldi59 = aaldis[59],
				aaldi28 = aaldis[28], aaldi60 = aaldis[60],
				aaldi29 = aaldis[29], aaldi61 = aaldis[61],
				aaldi30 = aaldis[30], aaldi62 = aaldis[62],
				aaldi31 = aaldis[31], aaldi63 = aaldis[63];
		E2K_SET_AAU_AALDI(aaldi24, aaldi24, aaldi56);
		E2K_SET_AAU_AALDI(aaldi25, aaldi25, aaldi57);
		E2K_SET_AAU_AALDI(aaldi26, aaldi26, aaldi58);
		E2K_SET_AAU_AALDI(aaldi27, aaldi27, aaldi59);
		E2K_SET_AAU_AALDI(aaldi28, aaldi28, aaldi60);
		E2K_SET_AAU_AALDI(aaldi29, aaldi29, aaldi61);
		E2K_SET_AAU_AALDI(aaldi30, aaldi30, aaldi62);
		E2K_SET_AAU_AALDI(aaldi31, aaldi31, aaldi63);
	}
}

static	inline	void
set_all_aaldas(const e2k_aalda_t aaldas[])
{
#ifndef __LITTLE_ENDIAN
# error This loads must be little endian to not mix aaldas up (and the same goes to SAVE_AALDA)
#endif
	register u32    aalda0 = *(u32 *) (&aaldas[0]),
			aalda4 = *(u32 *) (&aaldas[4]),
			aalda8 = *(u32 *) (&aaldas[8]),
			aalda12 = *(u32 *) (&aaldas[12]),
			aalda16 = *(u32 *) (&aaldas[16]),
			aalda20 = *(u32 *) (&aaldas[20]),
			aalda24 = *(u32 *) (&aaldas[24]),
			aalda28 = *(u32 *) (&aaldas[28]),
			aalda32 = *(u32 *) (&aaldas[32]),
			aalda36 = *(u32 *) (&aaldas[36]),
			aalda40 = *(u32 *) (&aaldas[40]),
			aalda44 = *(u32 *) (&aaldas[44]),
			aalda48 = *(u32 *) (&aaldas[48]),
			aalda52 = *(u32 *) (&aaldas[52]),
			aalda56 = *(u32 *) (&aaldas[56]),
			aalda60 = *(u32 *) (&aaldas[60]);
	E2K_SET_AAU_AALDA(aalda0, aalda0, aalda32);
	E2K_SET_AAU_AALDA(aalda4, aalda4, aalda36);
	E2K_SET_AAU_AALDA(aalda8, aalda8, aalda40);
	E2K_SET_AAU_AALDA(aalda12, aalda12, aalda44);
	E2K_SET_AAU_AALDA(aalda16, aalda16, aalda48);
	E2K_SET_AAU_AALDA(aalda20, aalda20, aalda52);
	E2K_SET_AAU_AALDA(aalda24, aalda24, aalda56);
	E2K_SET_AAU_AALDA(aalda28, aalda28, aalda60);
}

/* set current array prefetch buffer indices values */
static inline void set_aau_aaldis_aaldas(const e2k_aau_t *const context)
{
	set_all_aaldis(context->aaldi);
	set_all_aaldas(context->aalda);
}

/* calculate current array prefetch buffer indices values
 * (see chapter 1.10.2 in "Scheduling") */
#define printk printk_fixed_args
static inline void
calculate_aau_aaldis_aaldas(const struct pt_regs *const regs,
		e2k_aau_t *const context)
{
	u64 areas, area_num, iter_count;
	/* get_user() is used here */
	WARN_ON_ONCE(__raw_irqs_disabled());

	memset(context->aalda, 0, sizeof(context->aalda));
	memset(context->aaldi, 0, sizeof(context->aaldi));

	/* See bug 33621 comment 2 and bug 52350 comment 29 */
	iter_count = get_lcnt(regs->ilcr) - get_lcnt(regs->lsr);
	if (get_ldmc(regs->lsr) && !get_lcnt(regs->lsr))
		iter_count += get_ecnt(regs->ilcr) - get_ecnt(regs->lsr) - 1;

	/*
	 * Calculate areas in the following order:
	 *
	 *   0 -> 32 -> 1 -> 33 -> 2 -> ... -> 62 -> 31 -> 63
	 *
	 * until all the set bits in aaldv are checked.
	 */
	for (area_num = 0, areas = AW(context->aaldv); areas != 0;
			areas &= ~(1UL << area_num),
			area_num = (area_num < 32) ? (area_num + 32)
						   : (area_num - 31)) {
		e2k_fapb_instr_t *fapb_addr;
		e2k_fapb_instr_t fapb;
		e2k_aalda_t tmp_aalda;
		u64 step, ind, iter;

		if (!(AW(context->aaldv) & (1UL << area_num)))
			continue;

		iter = iter_count + ((AW(context->aaldm) & (1UL << area_num))
				>> area_num);

		if (iter == 0) {
			AW(context->aaldv) &= ~(1UL << area_num);
			continue;
		}

		if (area_num < 32)
			fapb_addr = (e2k_fapb_instr_t *)
				(AS(regs->ctpr2).ta_base + 16 * area_num);
		else
			fapb_addr = (e2k_fapb_instr_t *)
					(AS(regs->ctpr2).ta_base + 8 +
						16 * (area_num - 32));

#if __LCC__ >= 120
		/*
		 * tmp is used to avoid compiler issue with passing
		 * union's fields into inline asm. Bug 76907.
		 */
		u64 tmp;

		if (get_user(tmp, (u64 *)fapb_addr))
			goto die;
		fapb.word = tmp;
#else
		if (get_user(AW(fapb), (u64 *)fapb_addr))
			goto die;
#endif

		if (area_num >= 32 && AS(fapb).dpl) {
			static int once = 1;
			if (unlikely(once)) {
				/* See bug #53880 */
				once = 0;
				printk("%s [%d]: AAU is working in dpl mode "
					"(FAPB at %p)\n", current->comm,
					current->pid, fapb_addr);
			}

			context->aalda[area_num] = context->aalda[area_num - 32];
			context->aaldi[area_num] = context->aaldi[area_num - 32];
			continue;
		}

		if (!AS(fapb).fmt)
			continue;

		AS(tmp_aalda).root = (AS(context->aads[AS(fapb).d]).lo.tag ==
				AAD_AAUDS);

		if (AS(fapb).si) {
			AS(tmp_aalda).cincr = 0;
			AS(tmp_aalda).exc = 0;
			context->aalda[area_num] = tmp_aalda;
			continue;
		}

		ind = (context->aainds[AS(fapb).ind] + AS(fapb).disp)
				& 0xffffffffULL;
		step = (context->aaincrs[AS(fapb).incr] << (AS(fapb).fmt - 1))
				& 0xffffffffULL;
		if (context->aaincrs[AS(fapb).incr] >> 31)
			step = step | 0xffffffff00000000ULL;
		ind += step * iter;
		if (ind >> 32) {
			AS(tmp_aalda).cincr = 1;
			AS(tmp_aalda).exc = AALDA_EIO;
		} else {
			AS(tmp_aalda).cincr = 0;
			AS(tmp_aalda).exc = 0;
		}

		context->aalda[area_num] = tmp_aalda;

		context->aaldi[area_num] = ind & 0xffffffffULL;
	}

	return;

die:
	force_sig(SIGSEGV, current);
}
#undef printk

/* 
 * for code optimization
 */ 
static inline int aau_working(e2k_aau_t *context)
{
	e2k_aasr_t aasr = context->aasr;

	return unlikely(AW(aasr) & (AAU_AASR_IAB | AAU_AASR_STB));
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
static inline void
get_aau_context(e2k_aau_t *context)
{
	/* get registers, which describe arrays in APB operations */
	e2k_aasr_t aasr = context->aasr;

	/* get descriptors & auxiliary registers */
	if (AS(aasr).iab)
		get_array_descriptors(context);

	/* get synchronous part of APB */
	if (AS(aasr).stb)
		get_synchronous_part(context);
}

/* 
 * It's taken that comparison with aasr.iab was taken and assr
 * will be set later.
 */
static __always_inline void
set_aau_context(e2k_aau_t *context)
{
	/* retrieve common APB status register */
	e2k_aasr_t aasr = context->aasr;

	/* set synchronous part of APB */
	if (AS(aasr).stb) {
		prefetchw_range(context->aastis, sizeof(context->aastis)
				+ sizeof(context->aasti_tags));
		set_synchronous_part(context);
	}

	/* set descriptors & auxiliary registers */
	if (AS(aasr).iab) {
		prefetchw_range(context->aainds, sizeof(context->aainds)
				+ sizeof(context->aaind_tags)
				+ sizeof(context->aaincrs)
				+ sizeof(context->aaincr_tags)
				+ sizeof(context->aads)
				+ sizeof(context->aaldi)
				+ sizeof(context->aalda));
		set_array_descriptors(context);
	}
}
#endif /* _E2K_AAU_CONTEXT_H */
