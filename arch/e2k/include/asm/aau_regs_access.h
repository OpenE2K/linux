/*
 * AAU registers description, macroses for load/store AAU context
 *
 * array access descriptors			(AAD0, ... , AAD31);
 * initial indices				(AIND0, ... , AAIND15);
 * indices increment values			(AAINCR0, ... , AAINCR7);
 * current values of "prefetch" indices		(AALDI0, ... , AALDI63);
 * array prefetch initialization mask		(AALDV);
 * prefetch attributes				(AALDA0, ... , AALDA63);
 * array prefetch advance mask			(AALDM);
 * array access status register			(AASR);
 * array access fault status register		(AAFSTR);
 * current values of "store" indices		(AASTI0, ... , AASTI15);
 * store attributes				(AASTA0, ... , AASTA15);
 */

#ifndef _E2K_AAU_REGS_ACCESS_H_
#define _E2K_AAU_REGS_ACCESS_H_

#include <linux/types.h>
#include <asm/aau_regs_types.h>

#include <asm/native_aau_regs_access.h>

/*
 * see comment about of PREFIX_ at top of arch/e2k/include/regs_state.h
 * + additional parameter:
 * pv_type argument in macroses is same as prefix but by small letter
 * and can be:
 *	native		native kernel with or without virtualization support
 *	kvm		guest kernel (can be run only as paravirtualized
 *			guest kernel)
 *	pv		paravirtualized kernel (can be run as host and as guest
 *			paravirtualized kernels)
 */

#define	PREFIX_SAVE_AAU_MASK_REGS(PV_TYPE, pv_type, aau_context, aasr)	\
({									\
	if (unlikely(AAU_ACTIVE(aasr))) {				\
		/* As it turns out AAU can be in ACTIVE state		\
		 * in interrupt handler (bug 53227 comment 28		\
		 * and bug 53227 comment 36).				\
		 * The hardware stops AAU automatically but		\
		 * the value to be written should be corrected		\
		 * to "stopped" so that the "DONE" instruction		\
		 * works as expected.					\
		 */							\
		AS(aasr).lds = AASR_STOPPED;				\
	}								\
	(aau_context)->aasr = aasr;					\
	if (unlikely(AAU_STOPPED(aasr))) {				\
		pv_type##_read_aaldv_reg(&(aau_context)->aaldv);	\
		pv_type##_read_aaldm_reg(&(aau_context)->aaldm);	\
	} else {							\
		AW((aau_context)->aaldv) = 0;				\
		AW((aau_context)->aaldm) = 0;				\
	}								\
})

#define	NATIVE_SAVE_AAU_MASK_REGS(aau_context, aasr)	\
		PREFIX_SAVE_AAU_MASK_REGS(NATIVE, native, aau_context, aasr)

#define	PREFIX_RESTORE_AAU_MASK_REGS(PV_TYPE, pv_type, aau_context)	\
({									\
	pv_type##_write_aafstr_reg_value(0);				\
	pv_type##_write_aaldm_reg(&(aau_context)->aaldm);		\
	pv_type##_write_aaldv_reg(&(aau_context)->aaldv);		\
	/* aasr can be in 'ACTIVE' state, so we set it last */		\
	pv_type##_write_aasr_reg((aau_context)->aasr);		\
})

#define	NATIVE_RESTORE_AAU_MASK_REGS(aau_context)	\
		PREFIX_RESTORE_AAU_MASK_REGS(NATIVE, native, aau_context)

#define PREFIX_SAVE_AADS(PV_TYPE, pv_type, aau_regs)			\
({									\
	register e2k_aadj_t *aads = (aau_regs)->aads;			\
									\
	pv_type##_read_aads_4_reg(0, &aads[0]);				\
	pv_type##_read_aads_4_reg(4, &aads[4]);				\
	pv_type##_read_aads_4_reg(8, &aads[8]);				\
	pv_type##_read_aads_4_reg(12, &aads[12]);			\
	pv_type##_read_aads_4_reg(16, &aads[16]);			\
	pv_type##_read_aads_4_reg(20, &aads[20]);			\
	pv_type##_read_aads_4_reg(24, &aads[24]);			\
	pv_type##_read_aads_4_reg(28, &aads[28]);			\
})

#define NATIVE_SAVE_AADS(aau_regs)	\
		PREFIX_SAVE_AADS(NATIVE, native, aau_regs)

#define PREFIX_RESTORE_AADS(PV_TYPE, pv_type, aau_regs)			\
({									\
	register e2k_aadj_t *aads = (aau_regs)->aads;			\
									\
	pv_type##_write_aads_4_reg(0, &aads[0]);			\
	pv_type##_write_aads_4_reg(4, &aads[4]);			\
	pv_type##_write_aads_4_reg(8, &aads[8]);			\
	pv_type##_write_aads_4_reg(12, &aads[12]);			\
	pv_type##_write_aads_4_reg(16, &aads[16]);			\
	pv_type##_write_aads_4_reg(20, &aads[20]);			\
	pv_type##_write_aads_4_reg(24, &aads[24]);			\
	pv_type##_write_aads_4_reg(28, &aads[28]);			\
})

#define NATIVE_RESTORE_AADS(aau_regs)	\
		PREFIX_RESTORE_AADS(NATIVE, native, aau_regs)

#define PREFIX_SAVE_AALDIS(PV_TYPE, pv_type, ISET, iset, regs)		\
({									\
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(0, regs[0], regs[32]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(1, regs[1], regs[33]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(2, regs[2], regs[34]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(3, regs[3], regs[35]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(4, regs[4], regs[36]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(5, regs[5], regs[37]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(6, regs[6], regs[38]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(7, regs[7], regs[39]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(8, regs[8], regs[40]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(9, regs[9], regs[41]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(10, regs[10], regs[42]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(11, regs[11], regs[43]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(12, regs[12], regs[44]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(13, regs[13], regs[45]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(14, regs[14], regs[46]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(15, regs[15], regs[47]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(16, regs[16], regs[48]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(17, regs[17], regs[49]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(18, regs[18], regs[50]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(19, regs[19], regs[51]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(20, regs[20], regs[52]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(21, regs[21], regs[53]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(22, regs[22], regs[54]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(23, regs[23], regs[55]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(24, regs[24], regs[56]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(25, regs[25], regs[57]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(26, regs[26], regs[58]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(27, regs[27], regs[59]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(28, regs[28], regs[60]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(29, regs[29], regs[61]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(30, regs[30], regs[62]); \
	PV_TYPE##_READ_AALDI_REG_VALUE_##ISET(31, regs[31], regs[63]); \
})
#define PREFIX_SAVE_AALDIS_V2(PV_TYPE, pv_type, regs)	\
		PREFIX_SAVE_AALDIS(PV_TYPE, pv_type, V2, v2, regs)
#define PREFIX_SAVE_AALDIS_V5(PV_TYPE, pv_type, regs)	\
		PREFIX_SAVE_AALDIS(PV_TYPE, pv_type, V5, v5, regs)

#define NATIVE_SAVE_AALDIS_V2(regs)	\
		PREFIX_SAVE_AALDIS_V2(NATIVE, native, regs)
#define NATIVE_SAVE_AALDIS_V5(regs)	\
		PREFIX_SAVE_AALDIS_V5(NATIVE, native, regs)
#define NATIVE_SAVE_AALDIS(regs)	\
({ \
	if (IS_AAU_ISET_V5()) { \
		NATIVE_SAVE_AALDIS_V5(regs); \
	} else if (IS_AAU_ISET_V2()) { \
		NATIVE_SAVE_AALDIS_V2(regs); \
	} else if (IS_AAU_ISET_GENERIC()) { \
		machine.save_aaldi(regs); \
	} else { \
		BUILD_BUG_ON(true); \
	} \
})

#define	PREFIX_GET_ARRAY_DESCRIPTORS_V2(PV_TYPE, pv_type, aau_context)	\
({									\
	u64 *const aainds = (aau_context)->aainds;			\
	u64 *const aaincrs = (aau_context)->aaincrs;			\
									\
	/*								\
	 * get AAINDs, omit the AAIND0 saving since it has predefined 0	\
	 * value							\
	 */								\
	{								\
		register u32    ind1, ind2, ind3, ind4,			\
				ind5, ind6, ind7, ind8,			\
				ind9, ind10, ind11, ind12,		\
				ind13, ind14, ind15;			\
		register u32	tags;					\
									\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(1, ind1, ind2);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(3, ind3, ind4);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(5, ind5, ind6);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(7, ind7, ind8);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(9, ind9, ind10);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(11, ind11, ind12); \
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V2(13, ind13, ind14); \
		PV_TYPE##_READ_AAIND_REG15_AND_TAGS_VALUE_V2(ind15, tags); \
		aainds[0] = 0;						\
		aainds[1] = ind1;					\
		aainds[2] = ind2;					\
		aainds[3] = ind3;					\
		aainds[4] = ind4;					\
		aainds[5] = ind5;					\
		aainds[6] = ind6;					\
		aainds[7] = ind7;					\
		aainds[8] = ind8;					\
		aainds[9] = ind9;					\
		aainds[10] = ind10;					\
		aainds[11] = ind11;					\
		aainds[12] = ind12;					\
		aainds[13] = ind13;					\
		aainds[14] = ind14;					\
		aainds[15] = ind15;					\
		context->aaind_tags = tags;				\
	}								\
									\
	/*								\
	 * get AAINCRs, omit the AAINCR0 saving since it has predefined 1 \
	 * value							\
	 */								\
	{								\
		register u32	incr1, incr2, incr3, incr4,		\
				incr5, incr6, incr7;			\
		register u32	tags;					\
									\
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V2(1, incr1, incr2); \
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V2(3, incr3, incr4); \
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V2(5, incr5, incr6); \
		PV_TYPE##_READ_AAINCR_REG7_AND_TAGS_VALUE_V2(incr7, tags); \
		aaincrs[0] = 1;						\
		aaincrs[1] = (s64) (s32) incr1;				\
		aaincrs[2] = (s64) (s32) incr2;				\
		aaincrs[3] = (s64) (s32) incr3;				\
		aaincrs[4] = (s64) (s32) incr4;				\
		aaincrs[5] = (s64) (s32) incr5;				\
		aaincrs[6] = (s64) (s32) incr6;				\
		aaincrs[7] = (s64) (s32) incr7;				\
		context->aaincr_tags = tags;				\
	}								\
})
#define	NATIVE_GET_ARRAY_DESCRIPTORS_V2(aau_context)	\
		PREFIX_GET_ARRAY_DESCRIPTORS_V2(NATIVE, native, aau_context)

#define	PREFIX_GET_ARRAY_DESCRIPTORS_V5(PV_TYPE, pv_type, aau_context)	\
({									\
	u64 *const aainds = (aau_context)->aainds;			\
	u64 *const aaincrs = (aau_context)->aaincrs;			\
									\
	/*								\
	 * get AAINDs, omit the AAIND0 saving since it has predefined 0	\
	 * value							\
	 */								\
	{								\
		register u64	ind1, ind2, ind3, ind4,			\
				ind5, ind6, ind7, ind8,			\
				ind9, ind10, ind11, ind12,		\
				ind13, ind14, ind15;			\
		register u32	tags;					\
									\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(1, ind1, ind2);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(3, ind3, ind4);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(5, ind5, ind6);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(7, ind7, ind8);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(9, ind9, ind10);	\
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(11, ind11, ind12); \
		PV_TYPE##_READ_AAINDS_PAIR_VALUE_V5(13, ind13, ind14); \
		PV_TYPE##_READ_AAIND_REG15_AND_TAGS_VALUE_V5(ind15, tags); \
		aainds[0] = 0;						\
		aainds[1] = ind1;					\
		aainds[2] = ind2;					\
		aainds[3] = ind3;					\
		aainds[4] = ind4;					\
		aainds[5] = ind5;					\
		aainds[6] = ind6;					\
		aainds[7] = ind7;					\
		aainds[8] = ind8;					\
		aainds[9] = ind9;					\
		aainds[10] = ind10;					\
		aainds[11] = ind11;					\
		aainds[12] = ind12;					\
		aainds[13] = ind13;					\
		aainds[14] = ind14;					\
		aainds[15] = ind15;					\
		context->aaind_tags = tags;				\
	}								\
									\
	/*								\
	 * get AAINCRs, omit the AAINCR0 saving since it has predefined 1 \
	 * value							\
	 */								\
	{								\
		register u64	incr1, incr2, incr3, incr4,		\
				incr5, incr6, incr7;			\
		register u32	tags;					\
									\
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V5(1, incr1, incr2); \
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V5(3, incr3, incr4); \
		PV_TYPE##_READ_AAINCRS_PAIR_VALUE_V5(5, incr5, incr6); \
		PV_TYPE##_READ_AAINCR_REG7_AND_TAGS_VALUE_V5(incr7, tags); \
		aaincrs[0] = 1;						\
		aaincrs[1] = incr1;					\
		aaincrs[2] = incr2;					\
		aaincrs[3] = incr3;					\
		aaincrs[4] = incr4;					\
		aaincrs[5] = incr5;					\
		aaincrs[6] = incr6;					\
		aaincrs[7] = incr7;					\
		context->aaincr_tags = tags;				\
	}								\
})
#define	NATIVE_GET_ARRAY_DESCRIPTORS_V5(aau_context)	\
		PREFIX_GET_ARRAY_DESCRIPTORS_V5(NATIVE, native, aau_context)

#define	PREFIX_SET_ARRAY_DESCRIPTORS(PV_TYPE, pv_type, aau_context)	\
({									\
	const e2k_aau_t *const aau = (aau_context);			\
	const u64 *const aainds = aau->aainds;				\
	const u64 *const aaincrs = aau->aaincrs;			\
									\
	/*								\
	 * set AAINDs, omit the AAIND0 restoring since			\
	 * it has predefined 0 value.					\
	 */								\
	pv_type##_write_aainds_pair_value(1, aainds[1], aainds[2]);	\
	pv_type##_write_aainds_pair_value(3, aainds[3], aainds[4]);	\
	pv_type##_write_aainds_pair_value(5, aainds[5], aainds[6]);	\
	pv_type##_write_aainds_pair_value(7, aainds[7], aainds[8]);	\
	pv_type##_write_aainds_pair_value(9, aainds[9], aainds[10]);	\
	pv_type##_write_aainds_pair_value(11, aainds[11], aainds[12]);	\
	pv_type##_write_aainds_pair_value(13, aainds[13], aainds[14]);	\
	pv_type##_write_aaind_reg_value(15, aainds[15]);		\
									\
	/*								\
	 * set AAINCRs, omit the AAINCR0 restoring since		\
	 * it has predefined 1 value.					\
	 */								\
	pv_type##_write_aaincrs_pair_value(1, aaincrs[1], aaincrs[2]);	\
	pv_type##_write_aaincrs_pair_value(3, aaincrs[3], aaincrs[4]);	\
	pv_type##_write_aaincrs_pair_value(5, aaincrs[5], aaincrs[6]);	\
	pv_type##_write_aaincr_reg_value(7, aaincrs[7]);		\
									\
	/* Set TAGS */							\
	PV_TYPE##_SET_AAU_AAIND_AAINCR_TAGS(aau->aaind_tags, aau->aaincr_tags); \
})
#define	NATIVE_SET_ARRAY_DESCRIPTORS(aau_context)	\
		PREFIX_SET_ARRAY_DESCRIPTORS(NATIVE, native, aau_context)

#define	PREFIX_GET_SYNCHRONOUS_PART_V2(PV_TYPE, pv_type, aau_context)	\
({									\
	u64	*const aastis = (aau_context)->aastis;			\
	register u32	sti0, sti1, sti2, sti3,				\
			sti4, sti5, sti6, sti7,				\
			sti8, sti9, sti10, sti11,			\
			sti12, sti13, sti14, sti15;			\
									\
	/* get AASTIs */						\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(0, sti0, sti1);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(2, sti2, sti3);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(4, sti4, sti5);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(6, sti6, sti7);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(8, sti8, sti9);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(10, sti10, sti11);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(12, sti12, sti13);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V2(14, sti14, sti15);		\
									\
	aastis[0] = sti0;						\
	aastis[1] = sti1;						\
	aastis[2] = sti2;						\
	aastis[3] = sti3;						\
	aastis[4] = sti4;						\
	aastis[5] = sti5;						\
	aastis[6] = sti6;						\
	aastis[7] = sti7;						\
	aastis[8] = sti8;						\
	aastis[9] = sti9;						\
	aastis[10] = sti10;						\
	aastis[11] = sti11;						\
	aastis[12] = sti12;						\
	aastis[13] = sti13;						\
	aastis[14] = sti14;						\
	aastis[15] = sti15;						\
	(aau_context)->aasti_tags =					\
		pv_type##_read_aasti_tags_reg_value();			\
})

#define	PREFIX_GET_SYNCHRONOUS_PART_V5(PV_TYPE, pv_type, aau_context)	\
({									\
	u64	*const aastis = (aau_context)->aastis;			\
	register u64	sti0, sti1, sti2, sti3,				\
			sti4, sti5, sti6, sti7,				\
			sti8, sti9, sti10, sti11,			\
			sti12, sti13, sti14, sti15;			\
									\
	/* get AASTIs */						\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(0, sti0, sti1);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(2, sti2, sti3);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(4, sti4, sti5);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(6, sti6, sti7);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(8, sti8, sti9);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(10, sti10, sti11);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(12, sti12, sti13);		\
	PV_TYPE##_READ_AASTIS_PAIR_VALUE_V5(14, sti14, sti15);		\
									\
	aastis[0] = sti0;						\
	aastis[1] = sti1;						\
	aastis[2] = sti2;						\
	aastis[3] = sti3;						\
	aastis[4] = sti4;						\
	aastis[5] = sti5;						\
	aastis[6] = sti6;						\
	aastis[7] = sti7;						\
	aastis[8] = sti8;						\
	aastis[9] = sti9;						\
	aastis[10] = sti10;						\
	aastis[11] = sti11;						\
	aastis[12] = sti12;						\
	aastis[13] = sti13;						\
	aastis[14] = sti14;						\
	aastis[15] = sti15;						\
	(aau_context)->aasti_tags =					\
		pv_type##_read_aasti_tags_reg_value();		\
})
#define	NATIVE_GET_SYNCHRONOUS_PART_V2(aau_context)	\
		PREFIX_GET_SYNCHRONOUS_PART_V2(NATIVE, native, aau_context)
#define	NATIVE_GET_SYNCHRONOUS_PART_V5(aau_context)	\
		PREFIX_GET_SYNCHRONOUS_PART_V5(NATIVE, native, aau_context)

#define	PREFIX_SET_SYNCHRONOUS_PART(PV_TYPE, pv_type, aau_context)	\
({									\
	const u64 *const aastis = (aau_context)->aastis;		\
									\
	/* set AASTIs */						\
	pv_type##_write_aastis_pair_value(0, aastis[0], aastis[1]);	\
	pv_type##_write_aastis_pair_value(2, aastis[2], aastis[3]);	\
	pv_type##_write_aastis_pair_value(4, aastis[4], aastis[5]);	\
	pv_type##_write_aastis_pair_value(6, aastis[6], aastis[7]);	\
	pv_type##_write_aastis_pair_value(8, aastis[8], aastis[9]);	\
	pv_type##_write_aastis_pair_value(10, aastis[10], aastis[11]);	\
	pv_type##_write_aastis_pair_value(12, aastis[12], aastis[13]);	\
	pv_type##_write_aastis_pair_value(14, aastis[14], aastis[15]);	\
	pv_type##_write_aasti_tags_reg_value((aau_context)->aasti_tags); \
})
#define	NATIVE_SET_SYNCHRONOUS_PART(aau_context)	\
		PREFIX_SET_SYNCHRONOUS_PART(NATIVE, native, aau_context)

#define	PREFIX_SET_ALL_AALDIS(PV_TYPE, pv_type, aaldis)			\
({									\
	pv_type##_write_aaldi_reg_value(0, aaldis[0], aaldis[32]);	\
	pv_type##_write_aaldi_reg_value(1, aaldis[1], aaldis[33]);	\
	pv_type##_write_aaldi_reg_value(2, aaldis[2], aaldis[34]);	\
	pv_type##_write_aaldi_reg_value(3, aaldis[3], aaldis[35]);	\
	pv_type##_write_aaldi_reg_value(4, aaldis[4], aaldis[36]);	\
	pv_type##_write_aaldi_reg_value(5, aaldis[5], aaldis[37]);	\
	pv_type##_write_aaldi_reg_value(6, aaldis[6], aaldis[38]);	\
	pv_type##_write_aaldi_reg_value(7, aaldis[7], aaldis[39]);	\
	pv_type##_write_aaldi_reg_value(8, aaldis[8], aaldis[40]);	\
	pv_type##_write_aaldi_reg_value(9, aaldis[9], aaldis[41]);	\
	pv_type##_write_aaldi_reg_value(10, aaldis[10], aaldis[42]);	\
	pv_type##_write_aaldi_reg_value(11, aaldis[11], aaldis[43]);	\
	pv_type##_write_aaldi_reg_value(12, aaldis[12], aaldis[44]);	\
	pv_type##_write_aaldi_reg_value(13, aaldis[13], aaldis[45]);	\
	pv_type##_write_aaldi_reg_value(14, aaldis[14], aaldis[46]);	\
	pv_type##_write_aaldi_reg_value(15, aaldis[15], aaldis[47]);	\
	pv_type##_write_aaldi_reg_value(16, aaldis[16], aaldis[48]);	\
	pv_type##_write_aaldi_reg_value(17, aaldis[17], aaldis[49]);	\
	pv_type##_write_aaldi_reg_value(18, aaldis[18], aaldis[50]);	\
	pv_type##_write_aaldi_reg_value(19, aaldis[19], aaldis[51]);	\
	pv_type##_write_aaldi_reg_value(20, aaldis[20], aaldis[52]);	\
	pv_type##_write_aaldi_reg_value(21, aaldis[21], aaldis[53]);	\
	pv_type##_write_aaldi_reg_value(22, aaldis[22], aaldis[54]);	\
	pv_type##_write_aaldi_reg_value(23, aaldis[23], aaldis[55]);	\
	pv_type##_write_aaldi_reg_value(24, aaldis[24], aaldis[56]);	\
	pv_type##_write_aaldi_reg_value(25, aaldis[25], aaldis[57]);	\
	pv_type##_write_aaldi_reg_value(26, aaldis[26], aaldis[58]);	\
	pv_type##_write_aaldi_reg_value(27, aaldis[27], aaldis[59]);	\
	pv_type##_write_aaldi_reg_value(28, aaldis[28], aaldis[60]);	\
	pv_type##_write_aaldi_reg_value(29, aaldis[29], aaldis[61]);	\
	pv_type##_write_aaldi_reg_value(30, aaldis[30], aaldis[62]);	\
	pv_type##_write_aaldi_reg_value(31, aaldis[31], aaldis[63]);	\
})
#define	NATIVE_SET_ALL_AALDIS(aaldis)	\
		PREFIX_SET_ALL_AALDIS(NATIVE, native, aaldis)

#define	PREFIX_SET_ALL_AALDAS(PV_TYPE, pv_type, aaldas_p)		\
({									\
	register u32 *aaldas = (u32 *)(aaldas_p);			\
									\
	pv_type##_write_aaldas_reg_value(0, aaldas[0], aaldas[8]);	\
	pv_type##_write_aaldas_reg_value(4, aaldas[1], aaldas[9]);	\
	pv_type##_write_aaldas_reg_value(8, aaldas[2], aaldas[10]);	\
	pv_type##_write_aaldas_reg_value(12, aaldas[3], aaldas[11]);	\
	pv_type##_write_aaldas_reg_value(16, aaldas[4], aaldas[12]);	\
	pv_type##_write_aaldas_reg_value(20, aaldas[5], aaldas[13]);	\
	pv_type##_write_aaldas_reg_value(24, aaldas[6], aaldas[14]);	\
	pv_type##_write_aaldas_reg_value(28, aaldas[7], aaldas[15]);	\
})

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
#define	PREFIX_GET_AAU_CONTEXT(PV_TYPE, pv_type, ISET, iset, aau_context) \
({									\
	/* get registers, which describe arrays in APB operations */	\
	e2k_aasr_t aasr = (aau_context)->aasr;				\
									\
	/* get descriptors & auxiliary registers */			\
	if (AS(aasr).iab)						\
		PV_TYPE##_GET_ARRAY_DESCRIPTORS_##ISET(aau_context); \
									\
	/* get synchronous part of APB */				\
	if (AS(aasr).stb)						\
		PV_TYPE##_GET_SYNCHRONOUS_PART_##ISET(aau_context);	\
})
#define	PREFIX_GET_AAU_CONTEXT_V2(PV_TYPE, pv_type, aau_context)	\
		PREFIX_GET_AAU_CONTEXT(PV_TYPE, pv_type, V2, v2, aau_context)
#define	PREFIX_GET_AAU_CONTEXT_V5(PV_TYPE, pv_type, aau_context)	\
		PREFIX_GET_AAU_CONTEXT(PV_TYPE, pv_type, V5, v5, aau_context)
#define	NATIVE_GET_AAU_CONTEXT_V2(aau_context)	\
		PREFIX_GET_AAU_CONTEXT_V2(NATIVE, native, aau_context)
#define	NATIVE_GET_AAU_CONTEXT_V5(aau_context)	\
		PREFIX_GET_AAU_CONTEXT_V5(NATIVE, native, aau_context)
#define NATIVE_GET_AAU_CONTEXT(aau_context)	\
({ \
	if (IS_AAU_ISET_V5()) { \
		NATIVE_GET_AAU_CONTEXT_V5(aau_context); \
	} else if (IS_AAU_ISET_V2()) { \
		NATIVE_GET_AAU_CONTEXT_V2(aau_context); \
	} else if (IS_AAU_ISET_GENERIC()) { \
		machine.get_aau_context(aau_context); \
	} else { \
		BUILD_BUG_ON(true); \
	} \
})

/*
 * It's taken that comparison with aasr.iab was taken and assr
 * will be set later.
 */
#define	PREFIX_SET_AAU_CONTEXT(PV_TYPE, pv_type, aau_context) \
do { \
	const e2k_aau_t *const aau = (aau_context); \
	/* retrieve common APB status register */\
	e2k_aasr_t aasr = aau->aasr; \
 \
	/* prefetch data to restore */ \
	if (AS(aasr).stb) \
		prefetch_nospec_range(aau->aastis, sizeof(aau->aastis) + \
					     sizeof(aau->aasti_tags)); \
	if (AS(aasr).iab) \
		prefetch_nospec_range(aau->aainds, sizeof(aau->aainds) + \
				sizeof(aau->aaind_tags) + sizeof(aau->aaincrs) + \
				sizeof(aau->aaincr_tags) + sizeof(aau->aads)); \
	if (AAU_STOPPED(aasr)) \
		prefetch_nospec_range(aau->aaldi, sizeof(aau->aaldi)); \
 \
	/* Make sure prefetches are issued */ \
	barrier(); \
 \
	/* set synchronous part of APB */ \
	if (AS(aasr).stb) \
		pv_type##_set_synchronous_part(aau); \
 \
	/* set descriptors & auxiliary registers */ \
	if (AS(aasr).iab) \
		pv_type##_set_array_descriptors(aau); \
} while (0)
#define	NATIVE_SET_AAU_CONTEXT(aau_context)	\
		PREFIX_SET_AAU_CONTEXT(NATIVE, native, aau_context)

#define PREFIX_SAVE_AALDAS(PV_TYPE, pv_type, aaldas_p)			\
({									\
	register u32 *aaldas = (u32 *)aaldas_p;				\
									\
	pv_type##_read_aaldas_reg_value(0, &aaldas[0], &aaldas[8]);	\
	pv_type##_read_aaldas_reg_value(4, &aaldas[1], &aaldas[9]);	\
	pv_type##_read_aaldas_reg_value(8, &aaldas[2], &aaldas[10]);	\
	pv_type##_read_aaldas_reg_value(12, &aaldas[3], &aaldas[11]);	\
	pv_type##_read_aaldas_reg_value(16, &aaldas[4], &aaldas[12]);	\
	pv_type##_read_aaldas_reg_value(20, &aaldas[5], &aaldas[13]);	\
	pv_type##_read_aaldas_reg_value(24, &aaldas[6], &aaldas[14]);	\
	pv_type##_read_aaldas_reg_value(28, &aaldas[7], &aaldas[15]);	\
})

#define NATIVE_SAVE_AALDAS(aaldas_p)	\
		PREFIX_SAVE_AALDAS(NATIVE, native, aaldas_p)

#define PREFIX_SAVE_AAFSTR(PV_TYPE, pv_type, aau_context)		\
({									\
	(aau_context)->aafstr = pv_type##_read_aafstr_reg_value();	\
})

#define NATIVE_SAVE_AAFSTR(aau_context)	\
		PREFIX_SAVE_AAFSTR(NATIVE, native, aau_context)

#define PREFIX_SAVE_AAU_REGS_FOR_PTRACE(PV_TYPE, pv_type, pt_regs, ti)	\
({									\
	e2k_aau_t *__aau_context = (pt_regs)->aau_context;		\
	if (__aau_context) {						\
		if (machine.native_iset_ver < E2K_ISET_V6)		\
			PV_TYPE##_SAVE_AALDIS(__aau_context->aaldi);	\
		PV_TYPE##_SAVE_AALDAS(ti->aalda);			\
		PV_TYPE##_SAVE_AAFSTR(__aau_context);			\
	}								\
})

#define NATIVE_SAVE_AAU_REGS_FOR_PTRACE(pt_regs, ti)	\
		PREFIX_SAVE_AAU_REGS_FOR_PTRACE(NATIVE, native, pt_regs, ti)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure guest kernel without paravirtualization */
#include <asm/kvm/aau_regs_access.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized host and guest kernel */
#include <asm/paravirt/aau_regs_access.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* native kernel without virtualization */
/* or native host kernel with virtualization support */

static __always_inline u32 read_aasr_reg_value(void)
{
	return native_read_aasr_reg_value();
}
static __always_inline void write_aasr_reg_value(u32 reg_value)
{
	native_write_aasr_reg_value(reg_value);
}
static inline u32 read_aafstr_reg_value(void)
{
	return native_read_aafstr_reg_value();
}
static inline void write_aafstr_reg_value(u32 reg_value)
{
	native_write_aafstr_reg_value(reg_value);
}

static __always_inline e2k_aasr_t read_aasr_reg(void)
{
	return native_read_aasr_reg();
}
static __always_inline void write_aasr_reg(e2k_aasr_t aasr)
{
	native_write_aasr_reg(aasr);
}
static inline void read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	native_read_aaldm_reg(aaldm);
}
static inline void write_aaldm_reg(e2k_aaldm_t *aaldm)
{
	native_write_aaldm_reg(aaldm);
}
static inline void read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	native_read_aaldv_reg(aaldv);
}
static inline void write_aaldv_reg(e2k_aaldv_t *aaldv)
{
	native_write_aaldv_reg(aaldv);
}

#define clear_apb()	native_clear_apb()

#ifdef CONFIG_USE_AAU
# define SAVE_AAU_REGS_FOR_PTRACE(__regs, ti) \
		NATIVE_SAVE_AAU_REGS_FOR_PTRACE(__regs, ti)
#else
# define SAVE_AAU_REGS_FOR_PTRACE(__regs, ti)
#endif

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#define SWITCH_GUEST_AAU_AASR(aasr, aau_context, do_switch)	\
({ \
	if (do_switch) { \
		e2k_aasr_t aasr_worst_case; \
		AW(aasr_worst_case) = 0; \
		AS(aasr_worst_case).stb = 1; \
		AS(aasr_worst_case).iab = 1; \
		AS(aasr_worst_case).lds = AASR_STOPPED; \
		(aau_context)->guest_aasr = *(aasr); \
		*(aasr) = aasr_worst_case; \
	} \
})

#define RESTORE_GUEST_AAU_AASR(aau_context, do_restore)	\
({ \
	if (do_restore) { \
		(aau_context)->aasr = (aau_context)->guest_aasr; \
	} \
})

#endif /* _E2K_AAU_REGS_ACCESS_H_ */
