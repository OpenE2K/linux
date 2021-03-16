/*
 * Native hardware AAU registers access
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

#ifndef _NATIVE_AAU_REGS_ACCESS_H_
#define _NATIVE_AAU_REGS_ACCESS_H_

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/alternative.h>
#include <asm/cpu_regs_types.h>
#include <asm/e2k_api.h>
#include <asm/aau_regs_types.h>

#ifdef	DEBUG_AAU_REG_MODE
 #define	BUG_AAU()	BUG_ON(true)
#else	/* ! DEBUG_AAU_REG_MODE */
 #define	BUG_AAU()
#endif	/* DEBUG_AAU_REG_MODE */

/* macros to access to native hardware E2K AAU context */

#define NATIVE_GET_AAU_AAD(reg_mn, mem_p)		\
		NATIVE_GET_AAUQREG(&AWP(mem_p), reg_mn)
#define NATIVE_GET_AAU_AADS(reg1, reg2, reg3, reg4, mem_p) \
		NATIVE_GET_AAUQREGS(&AWP(mem_p), reg1, reg2, reg3, reg4)
#define NATIVE_GET_AAU_AAIND_V2(reg_mnemonic)		\
		NATIVE_GET_AAUREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AAIND_V5(reg_mnemonic)		\
		NATIVE_GET_AAUDREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AAINDS_V2(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AAINDS_V5(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AAIND_TAG()			\
		NATIVE_GET_AAUREG(aaind_tag, 2)
#define NATIVE_GET_AAU_AAINCR_V2(reg_mnemonic)		\
		NATIVE_GET_AAUREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AAINCR_V5(reg_mnemonic)		\
		NATIVE_GET_AAUDREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AAINCRS_V2(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AAINCRS_V5(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AAINCR_TAG()			\
		NATIVE_GET_AAUREG(aaincr_tag, 2)
#define NATIVE_GET_AAU_AASTI_V2(reg_mnemonic)		\
		NATIVE_GET_AAUREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AASTI_V5(reg_mnemonic)		\
		NATIVE_GET_AAUDREG(reg_mnemonic, 2)
#define NATIVE_GET_AAU_AASTIS_V2(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AASTIS_V5(reg1, reg2, val1, val2)	\
		NATIVE_GET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_GET_AAU_AASTI_TAG()			\
		NATIVE_GET_AAUREG(aasti_tag, 2)
#define NATIVE_GET_AAU_AASR()				\
		NATIVE_GET_AAUREG(aasr, 2)
#define NATIVE_GET_AAU_AAFSTR()				\
		NATIVE_GET_AAUREG(aafstr, 5)
#define NATIVE_GET_AAU_AALDI_V2(reg_mn, lval, rval)	\
		NATIVE_GET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define NATIVE_GET_AAU_AALDI_V5(reg_mn, lval, rval)	\
		NATIVE_GET_AAUDREGS(reg_mn, reg_mn, lval, rval)
#define NATIVE_GET_AAU_AALDA(reg_mn, lval, rval)	\
		NATIVE_GET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define NATIVE_GET_AAU_AALDV(lo, hi)			\
		NATIVE_GET_AAUREGS(aaldv, aaldv, lo, hi)
#define NATIVE_GET_AAU_AALDM(lo, hi)			\
		NATIVE_GET_AAUREGS(aaldm, aaldm, lo, hi)

#define NATIVE_SET_AAU_AAD(reg_mn, mem_p)		\
		NATIVE_SET_AAUQREG(reg_mn, &AWP(mem_p))
#define NATIVE_SET_AAU_AADS(reg1, reg2, reg3, reg4, mem_p) \
		NATIVE_SET_AAUQREGS(&AWP(mem_p), reg1, reg2, reg3, reg4)
#define NATIVE_SET_AAU_AAIND(reg_mn, val)		\
		NATIVE_SET_AAUDREG(reg_mn, val, 2)
#define NATIVE_SET_AAU_AAINDS(reg1, reg2, val1, val2)	\
		NATIVE_SET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_SET_AAU_AAIND_TAG(val)			\
		NATIVE_SET_AAUREG(aaind_tag, val, 2)
#define NATIVE_SET_AAU_AAIND_REG_AND_TAGS(reg, reg_tag, val, tags_val)	\
		NATIVE_SET_AAUREGS(reg, reg_tag, val, tags_val)
#define NATIVE_SET_AAU_AAIND_AAINCR_TAGS(aaind, aaincr) \
		NATIVE_SET_AAUREGS(aaind_tag, aaincr_tag, (aaind), (aaincr))
#define NATIVE_SET_AAU_AAINCR(reg_mn, val)		\
		NATIVE_SET_AAUDREG(reg_mn, val, 5)
#define NATIVE_SET_AAU_AAINCRS(reg1, reg2, val1, val2)	\
		NATIVE_SET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_SET_AAU_AAINCR_TAG(val)			\
		NATIVE_SET_AAUREG(aaincr_tag, val, 5)
#define NATIVE_SET_AAU_AAINCR_REG_AND_TAGS(reg, reg_tag, val, tags_val)	\
		NATIVE_SET_AAUREGS(reg, reg_tag, val, tags_val)
#define NATIVE_SET_AAU_AASTI(reg_mn, val)		\
		NATIVE_SET_AAUDREG(reg_mn, val, 2)
#define NATIVE_SET_AAU_AASTIS(reg1, reg2, val1, val2)	\
		NATIVE_SET_AAUDREGS(reg1, reg2, val1, val2)
#define NATIVE_SET_AAU_AASTI_TAG(val)			\
		NATIVE_SET_AAUREG(aasti_tag, val, 2)
#define NATIVE_SET_AAU_AASR(val)			\
		NATIVE_SET_AAUREG(aasr, val, 2)
#define NATIVE_SET_AAU_AAFSTR(val)			\
		NATIVE_SET_AAUREG(aafstr, val, 5)
#define NATIVE_SET_AAU_AALDI(reg_mn, lval, rval)	\
		NATIVE_SET_AAUDREGS(reg_mn, reg_mn, lval, rval)
#define NATIVE_SET_AAU_AALDA(reg_mn, lval, rval)	\
		NATIVE_SET_AAUREGS(reg_mn, reg_mn, lval, rval)
#define NATIVE_SET_AAU_AALDV(lo, hi)			\
		NATIVE_SET_AAUREGS(aaldv, aaldv, lo, hi)
#define NATIVE_SET_AAU_AALDM(lo, hi)			\
		NATIVE_SET_AAUREGS(aaldm, aaldm, lo, hi)

/*
 * Native hardware AAU registers access function (can be paravirtualized)
 * WARNING: please use only following functions to access to AAU context,
 * do not use macroses above directly, because of macroses cannot be
 * paravirtualized
 */

static __always_inline u32 native_read_aasr_reg_value(void)
{
	return NATIVE_GET_AAU_AASR();
}
static __always_inline void native_write_aasr_reg_value(u32 reg_value)
{
	NATIVE_SET_AAU_AASR(reg_value);
}
static inline u32 native_read_aafstr_reg_value(void)
{
	return NATIVE_GET_AAU_AAFSTR();
}
static __always_inline void native_write_aafstr_reg_value(u32 reg_value)
{
	NATIVE_SET_AAU_AAFSTR(reg_value);
}

static __always_inline e2k_aasr_t native_read_aasr_reg(void)
{
	e2k_aasr_t aasr;

	AW(aasr) = native_read_aasr_reg_value();
	return aasr;
}
static __always_inline void native_write_aasr_reg(e2k_aasr_t aasr)
{
	NATIVE_SET_AAU_AASR(AW(aasr));
}

static inline u32 native_read_aaind_reg_value_v2(int AAIND_no)
{
	switch (AAIND_no) {
	case  0: return NATIVE_GET_AAU_AAIND_V2(aaind0);
	case  1: return NATIVE_GET_AAU_AAIND_V2(aaind1);
	case  2: return NATIVE_GET_AAU_AAIND_V2(aaind2);
	case  3: return NATIVE_GET_AAU_AAIND_V2(aaind3);
	case  4: return NATIVE_GET_AAU_AAIND_V2(aaind4);
	case  5: return NATIVE_GET_AAU_AAIND_V2(aaind5);
	case  6: return NATIVE_GET_AAU_AAIND_V2(aaind6);
	case  7: return NATIVE_GET_AAU_AAIND_V2(aaind7);
	case  8: return NATIVE_GET_AAU_AAIND_V2(aaind8);
	case  9: return NATIVE_GET_AAU_AAIND_V2(aaind9);
	case 10: return NATIVE_GET_AAU_AAIND_V2(aaind10);
	case 11: return NATIVE_GET_AAU_AAIND_V2(aaind11);
	case 12: return NATIVE_GET_AAU_AAIND_V2(aaind12);
	case 13: return NATIVE_GET_AAU_AAIND_V2(aaind13);
	case 14: return NATIVE_GET_AAU_AAIND_V2(aaind14);
	case 15: return NATIVE_GET_AAU_AAIND_V2(aaind15);
	default:
		BUG_AAU();
		 return 0;
	}
}

static inline u64 native_read_aaind_reg_value_v5(int AAIND_no)
{
	switch (AAIND_no) {
	case  0: return NATIVE_GET_AAU_AAIND_V5(aaind0);
	case  1: return NATIVE_GET_AAU_AAIND_V5(aaind1);
	case  2: return NATIVE_GET_AAU_AAIND_V5(aaind2);
	case  3: return NATIVE_GET_AAU_AAIND_V5(aaind3);
	case  4: return NATIVE_GET_AAU_AAIND_V5(aaind4);
	case  5: return NATIVE_GET_AAU_AAIND_V5(aaind5);
	case  6: return NATIVE_GET_AAU_AAIND_V5(aaind6);
	case  7: return NATIVE_GET_AAU_AAIND_V5(aaind7);
	case  8: return NATIVE_GET_AAU_AAIND_V5(aaind8);
	case  9: return NATIVE_GET_AAU_AAIND_V5(aaind9);
	case 10: return NATIVE_GET_AAU_AAIND_V5(aaind10);
	case 11: return NATIVE_GET_AAU_AAIND_V5(aaind11);
	case 12: return NATIVE_GET_AAU_AAIND_V5(aaind12);
	case 13: return NATIVE_GET_AAU_AAIND_V5(aaind13);
	case 14: return NATIVE_GET_AAU_AAIND_V5(aaind14);
	case 15: return NATIVE_GET_AAU_AAIND_V5(aaind15);
	default:
		BUG_AAU();
		 return 0;
	}
}
static inline void native_write_aaind_reg_value(int AAIND_no, u64 reg_value)
{
	switch (AAIND_no) {
	case  0:
		NATIVE_SET_AAU_AAIND(aaind0, reg_value);
		break;
	case  1:
		NATIVE_SET_AAU_AAIND(aaind1, reg_value);
		break;
	case  2:
		NATIVE_SET_AAU_AAIND(aaind2, reg_value);
		break;
	case  3:
		NATIVE_SET_AAU_AAIND(aaind3, reg_value);
		break;
	case  4:
		NATIVE_SET_AAU_AAIND(aaind4, reg_value);
		break;
	case  5:
		NATIVE_SET_AAU_AAIND(aaind5, reg_value);
		break;
	case  6:
		NATIVE_SET_AAU_AAIND(aaind6, reg_value);
		break;
	case  7:
		NATIVE_SET_AAU_AAIND(aaind7, reg_value);
		break;
	case  8:
		NATIVE_SET_AAU_AAIND(aaind8, reg_value);
		break;
	case  9:
		NATIVE_SET_AAU_AAIND(aaind9, reg_value);
		break;
	case 10:
		NATIVE_SET_AAU_AAIND(aaind10, reg_value);
		break;
	case 11:
		NATIVE_SET_AAU_AAIND(aaind11, reg_value);
		break;
	case 12:
		NATIVE_SET_AAU_AAIND(aaind12, reg_value);
		break;
	case 13:
		NATIVE_SET_AAU_AAIND(aaind13, reg_value);
		break;
	case 14:
		NATIVE_SET_AAU_AAIND(aaind14, reg_value);
		break;
	case 15:
		NATIVE_SET_AAU_AAIND(aaind15, reg_value);
		break;
	default:
		BUG_AAU();
	}
}

#define PREFIX_READ_AAINDS_PAIR_VALUE(PV_TYPE, pv_type, ISET, iset, \
					AAINDs_pair, value1, value2) \
({ \
	switch (AAINDs_pair) { \
	case  0: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind0, aaind1, \
							value1, value2); \
		break; \
	case  1: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind1, aaind2, \
							value1, value2); \
		break; \
	case  2: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind2, aaind3, \
							value1, value2); \
		break; \
	case  3: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind3, aaind4, \
							value1, value2); \
		break; \
	case  4: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind4, aaind5, \
							value1, value2); \
		break; \
	case  5: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind5, aaind6, \
							value1, value2); \
		break; \
	case  6: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind6, aaind7, \
							value1, value2); \
		break; \
	case  7: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind7, aaind8, \
							value1, value2); \
		break; \
	case  8: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind8, aaind9, \
							value1, value2); \
		break; \
	case  9: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind9, aaind10, \
							value1, value2); \
		break; \
	case 10: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind10, aaind11, \
							value1, value2); \
		break; \
	case 11: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind11, aaind12, \
							value1, value2); \
		break; \
	case 12: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind12, aaind13, \
							value1, value2); \
		break; \
	case 13: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind13, aaind14, \
							value1, value2); \
		break; \
	case 14: \
		PV_TYPE##_GET_AAU_AAINDS_##ISET(aaind14, aaind15, \
							value1, value2); \
		break; \
	case 15: \
		value1 = PV_TYPE##_GET_AAU_AAIND_##ISET(aaind15); \
		value2 = PV_TYPE##_GET_AAU_AAIND_TAG(); \
		break; \
	default: \
		BUG_AAU(); \
		value1 = 0; \
		value2 = 0; \
	} \
})
#define NATIVE_READ_AAINDS_PAIR_VALUE_V2(AAINDs_pair, lo_value, hi_value) \
		PREFIX_READ_AAINDS_PAIR_VALUE(NATIVE, native, V2, v2, \
					AAINDs_pair, lo_value, hi_value)
#define NATIVE_READ_AAINDS_PAIR_VALUE_V5(AAINDs_pair, lo_value, hi_value) \
		PREFIX_READ_AAINDS_PAIR_VALUE(NATIVE, native, V5, v5, \
					AAINDs_pair, lo_value, hi_value)
#define PREFIX_READ_AAIND_REG15_AND_TAGS_VALUE_V2(PV_TYPE, pv_type, \
					reg_value, tags_value) \
({ \
	PV_TYPE##_GET_AAU_AAINDS_V2(aaind15, aaind_tag, \
					reg_value, tags_value); \
})
#define NATIVE_READ_AAIND_REG15_AND_TAGS_VALUE_V2(reg_value, tags_value) \
		PREFIX_READ_AAIND_REG15_AND_TAGS_VALUE_V2(NATIVE, native, \
					reg_value, tags_value)
#define PREFIX_READ_AAIND_REG15_AND_TAGS_VALUE_V5(PV_TYPE, pv_type, \
					reg_value, tags_value) \
({ \
	reg_value = PV_TYPE##_GET_AAU_AAIND_V5(aaind15); \
	tags_value = PV_TYPE##_GET_AAU_AAIND_TAG(); \
})
#define NATIVE_READ_AAIND_REG15_AND_TAGS_VALUE_V5(reg_value, tags_value) \
		PREFIX_READ_AAIND_REG15_AND_TAGS_VALUE_V5(NATIVE, native, \
					reg_value, tags_value)

static __always_inline void
native_write_aainds_pair_value(int AAINDs_pair, u64 lo_value, u64 hi_value)
{
	switch (AAINDs_pair) {
	case  0:
		NATIVE_SET_AAU_AAINDS(aaind0, aaind1, lo_value, hi_value);
		break;
	case  1:
		NATIVE_SET_AAU_AAINDS(aaind1, aaind2, lo_value, hi_value);
		break;
	case  2:
		NATIVE_SET_AAU_AAINDS(aaind2, aaind3, lo_value, hi_value);
		break;
	case  3:
		NATIVE_SET_AAU_AAINDS(aaind3, aaind4, lo_value, hi_value);
		break;
	case  4:
		NATIVE_SET_AAU_AAINDS(aaind4, aaind5, lo_value, hi_value);
		break;
	case  5:
		NATIVE_SET_AAU_AAINDS(aaind5, aaind6, lo_value, hi_value);
		break;
	case  6:
		NATIVE_SET_AAU_AAINDS(aaind6, aaind7, lo_value, hi_value);
		break;
	case  7:
		NATIVE_SET_AAU_AAINDS(aaind7, aaind8, lo_value, hi_value);
		break;
	case  8:
		NATIVE_SET_AAU_AAINDS(aaind8, aaind9, lo_value, hi_value);
		break;
	case  9:
		NATIVE_SET_AAU_AAINDS(aaind9, aaind10, lo_value, hi_value);
		break;
	case 10:
		NATIVE_SET_AAU_AAINDS(aaind10, aaind11, lo_value, hi_value);
		break;
	case 11:
		NATIVE_SET_AAU_AAINDS(aaind11, aaind12, lo_value, hi_value);
		break;
	case 12:
		NATIVE_SET_AAU_AAINDS(aaind12, aaind13, lo_value, hi_value);
		break;
	case 13:
		NATIVE_SET_AAU_AAINDS(aaind13, aaind14, lo_value, hi_value);
		break;
	case 14:
		NATIVE_SET_AAU_AAINDS(aaind14, aaind15, lo_value, hi_value);
		break;
	default:
		BUG_AAU();
	}
}

static inline u32 native_read_aaind_tags_reg_value(void)
{
	return NATIVE_GET_AAU_AAIND_TAG();
}
static inline void native_write_aaind_tags_reg_value(u32 reg_value)
{
	NATIVE_SET_AAU_AAIND_TAG(reg_value);
}
static inline u32 native_read_aaincr_reg_value_v2(int AAINCR_no)
{
	switch (AAINCR_no) {
	case  0: return NATIVE_GET_AAU_AAINCR_V2(aaincr0);
	case  1: return NATIVE_GET_AAU_AAINCR_V2(aaincr1);
	case  2: return NATIVE_GET_AAU_AAINCR_V2(aaincr2);
	case  3: return NATIVE_GET_AAU_AAINCR_V2(aaincr3);
	case  4: return NATIVE_GET_AAU_AAINCR_V2(aaincr4);
	case  5: return NATIVE_GET_AAU_AAINCR_V2(aaincr5);
	case  6: return NATIVE_GET_AAU_AAINCR_V2(aaincr6);
	case  7: return NATIVE_GET_AAU_AAINCR_V2(aaincr7);
	default:
		BUG_AAU();
		return 0;
	}
}
static inline u64 native_read_aaincr_reg_value_v5(int AAINCR_no)
{
	switch (AAINCR_no) {
	case  0: return NATIVE_GET_AAU_AAINCR_V5(aaincr0);
	case  1: return NATIVE_GET_AAU_AAINCR_V5(aaincr1);
	case  2: return NATIVE_GET_AAU_AAINCR_V5(aaincr2);
	case  3: return NATIVE_GET_AAU_AAINCR_V5(aaincr3);
	case  4: return NATIVE_GET_AAU_AAINCR_V5(aaincr4);
	case  5: return NATIVE_GET_AAU_AAINCR_V5(aaincr5);
	case  6: return NATIVE_GET_AAU_AAINCR_V5(aaincr6);
	case  7: return NATIVE_GET_AAU_AAINCR_V5(aaincr7);
	default:
		BUG_AAU();
		return 0;
	}
}
static inline void native_write_aaincr_reg_value(int AAINCR_no, u64 reg_value)
{
	switch (AAINCR_no) {
	case  0:
		NATIVE_SET_AAU_AAINCR(aaincr0, reg_value);
		break;
	case  1:
		NATIVE_SET_AAU_AAINCR(aaincr1, reg_value);
		break;
	case  2:
		NATIVE_SET_AAU_AAINCR(aaincr2, reg_value);
		break;
	case  3:
		NATIVE_SET_AAU_AAINCR(aaincr3, reg_value);
		break;
	case  4:
		NATIVE_SET_AAU_AAINCR(aaincr4, reg_value);
		break;
	case  5:
		NATIVE_SET_AAU_AAINCR(aaincr5, reg_value);
		break;
	case  6:
		NATIVE_SET_AAU_AAINCR(aaincr6, reg_value);
		break;
	case  7:
		NATIVE_SET_AAU_AAINCR(aaincr7, reg_value);
		break;
	default:
		BUG_AAU();
	}
}
static inline u32 native_read_aaincr_tags_reg_value(void)
{
	return NATIVE_GET_AAU_AAINCR_TAG();
}
static inline void native_write_aaincr_tags_reg_value(u32 reg_value)
{
	NATIVE_SET_AAU_AAINCR_TAG(reg_value);
}

#define	PREFIX_READ_AAINCRS_PAIR_VALUE(PV_TYPE, pv_type, ISET, iset, \
					AAINCRs_pair, value1, value2) \
({ \
	switch (AAINCRs_pair) { \
	case  0: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr0, aaincr1, \
							value1, value2); \
		break; \
	case  1: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr1, aaincr2, \
							value1, value2); \
		break; \
	case  2: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr2, aaincr3, \
							value1, value2); \
		break; \
	case  3: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr3, aaincr4, \
							value1, value2); \
		break; \
	case  4: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr4, aaincr5, \
							value1, value2); \
		break; \
	case  5: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr5, aaincr6, \
							value1, value2); \
		break; \
	case  6: \
		PV_TYPE##_GET_AAU_AAINCRS_##ISET(aaincr6, aaincr7, \
							value1, value2); \
		break; \
	case  7: \
		value1 = PV_TYPE##_GET_AAU_AAINCR_##ISET(aaind15); \
		value2 = PV_TYPE##_GET_AAU_AAINCR_TAG(); \
		break; \
	default: \
		BUG_AAU(); \
		 value1 = 0; \
		 value2 = 0; \
	} \
})
#define	NATIVE_READ_AAINCRS_PAIR_VALUE_V2(AAINCRs_pair, lo_value, hi_value) \
		PREFIX_READ_AAINCRS_PAIR_VALUE(NATIVE, native, V2, v2, \
					AAINCRs_pair, lo_value, hi_value)
#define	NATIVE_READ_AAINCRS_PAIR_VALUE_V5(AAINCRs_pair, lo_value, hi_value) \
		PREFIX_READ_AAINCRS_PAIR_VALUE(NATIVE, native, V5, v5, \
					AAINCRs_pair, lo_value, hi_value)
#define PREFIX_READ_AAINCR_REG7_AND_TAGS_VALUE_V2(PV_TYPE, pv_type, \
					reg_value, tags_value) \
({ \
	PV_TYPE##_GET_AAU_AAINCRS_V2(aaincr7, aaincr_tag, \
					reg_value, tags_value); \
})
#define NATIVE_READ_AAINCR_REG7_AND_TAGS_VALUE_V2(reg_value, tags_value) \
		PREFIX_READ_AAINCR_REG7_AND_TAGS_VALUE_V2(NATIVE, native, \
					reg_value, tags_value)
#define PREFIX_READ_AAINCR_REG7_AND_TAGS_VALUE_V5(PV_TYPE, pv_type, \
					reg_value, tags_value) \
({ \
	reg_value = PV_TYPE##_GET_AAU_AAINCR_V5(aaincr7); \
	tags_value = PV_TYPE##_GET_AAU_AAINCR_TAG(); \
})
#define NATIVE_READ_AAINCR_REG7_AND_TAGS_VALUE_V5(reg_value, tags_value) \
		PREFIX_READ_AAINCR_REG7_AND_TAGS_VALUE_V5(NATIVE, native, \
					reg_value, tags_value)

static __always_inline void
native_write_aaincrs_pair_value(int AAINCRs_pair, u64 lo_value, u64 hi_value)
{
	switch (AAINCRs_pair) {
	case  0:
		NATIVE_SET_AAU_AAINCRS(aaincr0, aaincr1, lo_value, hi_value);
		break;
	case  1:
		NATIVE_SET_AAU_AAINCRS(aaincr1, aaincr2, lo_value, hi_value);
		break;
	case  2:
		NATIVE_SET_AAU_AAINCRS(aaincr2, aaincr3, lo_value, hi_value);
		break;
	case  3:
		NATIVE_SET_AAU_AAINCRS(aaincr3, aaincr4, lo_value, hi_value);
		break;
	case  4:
		NATIVE_SET_AAU_AAINCRS(aaincr4, aaincr5, lo_value, hi_value);
		break;
	case  5:
		NATIVE_SET_AAU_AAINCRS(aaincr5, aaincr6, lo_value, hi_value);
		break;
	case  6:
		NATIVE_SET_AAU_AAINCRS(aaincr6, aaincr7, lo_value, hi_value);
		break;
	default:
		BUG_AAU();
	}
}

static inline u32 native_read_aasti_reg_value_v2(int AASTI_no)
{
	switch (AASTI_no) {
	case  0: return NATIVE_GET_AAU_AASTI_V2(aasti0);
	case  1: return NATIVE_GET_AAU_AASTI_V2(aasti1);
	case  2: return NATIVE_GET_AAU_AASTI_V2(aasti2);
	case  3: return NATIVE_GET_AAU_AASTI_V2(aasti3);
	case  4: return NATIVE_GET_AAU_AASTI_V2(aasti4);
	case  5: return NATIVE_GET_AAU_AASTI_V2(aasti5);
	case  6: return NATIVE_GET_AAU_AASTI_V2(aasti6);
	case  7: return NATIVE_GET_AAU_AASTI_V2(aasti7);
	case  8: return NATIVE_GET_AAU_AASTI_V2(aasti8);
	case  9: return NATIVE_GET_AAU_AASTI_V2(aasti9);
	case 10: return NATIVE_GET_AAU_AASTI_V2(aasti10);
	case 11: return NATIVE_GET_AAU_AASTI_V2(aasti11);
	case 12: return NATIVE_GET_AAU_AASTI_V2(aasti12);
	case 13: return NATIVE_GET_AAU_AASTI_V2(aasti13);
	case 14: return NATIVE_GET_AAU_AASTI_V2(aasti14);
	case 15: return NATIVE_GET_AAU_AASTI_V2(aasti15);
	default:
		BUG_AAU();
		return 0;
	}
}
static inline u64 native_read_aasti_reg_value_v5(int AASTI_no)
{
	switch (AASTI_no) {
	case  0: return NATIVE_GET_AAU_AASTI_V5(aasti0);
	case  1: return NATIVE_GET_AAU_AASTI_V5(aasti1);
	case  2: return NATIVE_GET_AAU_AASTI_V5(aasti2);
	case  3: return NATIVE_GET_AAU_AASTI_V5(aasti3);
	case  4: return NATIVE_GET_AAU_AASTI_V5(aasti4);
	case  5: return NATIVE_GET_AAU_AASTI_V5(aasti5);
	case  6: return NATIVE_GET_AAU_AASTI_V5(aasti6);
	case  7: return NATIVE_GET_AAU_AASTI_V5(aasti7);
	case  8: return NATIVE_GET_AAU_AASTI_V5(aasti8);
	case  9: return NATIVE_GET_AAU_AASTI_V5(aasti9);
	case 10: return NATIVE_GET_AAU_AASTI_V5(aasti10);
	case 11: return NATIVE_GET_AAU_AASTI_V5(aasti11);
	case 12: return NATIVE_GET_AAU_AASTI_V5(aasti12);
	case 13: return NATIVE_GET_AAU_AASTI_V5(aasti13);
	case 14: return NATIVE_GET_AAU_AASTI_V5(aasti14);
	case 15: return NATIVE_GET_AAU_AASTI_V5(aasti15);
	default:
		BUG_AAU();
		return 0;
	}
}
static inline void native_write_aasti_reg_value(int AASTI_no, u64 reg_value)
{
	switch (AASTI_no) {
	case  0:
		NATIVE_SET_AAU_AASTI(aasti0, reg_value);
		break;
	case  1:
		NATIVE_SET_AAU_AASTI(aasti1, reg_value);
		break;
	case  2:
		NATIVE_SET_AAU_AASTI(aasti2, reg_value);
		break;
	case  3:
		NATIVE_SET_AAU_AASTI(aasti3, reg_value);
		break;
	case  4:
		NATIVE_SET_AAU_AASTI(aasti4, reg_value);
		break;
	case  5:
		NATIVE_SET_AAU_AASTI(aasti5, reg_value);
		break;
	case  6:
		NATIVE_SET_AAU_AASTI(aasti6, reg_value);
		break;
	case  7:
		NATIVE_SET_AAU_AASTI(aasti7, reg_value);
		break;
	case  8:
		NATIVE_SET_AAU_AASTI(aasti8, reg_value);
		break;
	case  9:
		NATIVE_SET_AAU_AASTI(aasti9, reg_value);
		break;
	case 10:
		NATIVE_SET_AAU_AASTI(aasti10, reg_value);
		break;
	case 11:
		NATIVE_SET_AAU_AASTI(aasti11, reg_value);
		break;
	case 12:
		NATIVE_SET_AAU_AASTI(aasti12, reg_value);
		break;
	case 13:
		NATIVE_SET_AAU_AASTI(aasti13, reg_value);
		break;
	case 14:
		NATIVE_SET_AAU_AASTI(aasti14, reg_value);
		break;
	case 15:
		NATIVE_SET_AAU_AASTI(aasti15, reg_value);
		break;
	default:
		BUG_AAU();
	}
}
static inline u32 native_read_aasti_tags_reg_value(void)
{
	return NATIVE_GET_AAU_AASTI_TAG();
}
static inline void native_write_aasti_tags_reg_value(u32 reg_value)
{
	NATIVE_SET_AAU_AASTI_TAG(reg_value);
}

#define	PREFIX_READ_AASTIS_PAIR_VALUE(PV_TYPE, pv_type, ISET, iset, \
					AASTIs_pair, value1, value2) \
({ \
	switch (AASTIs_pair) { \
	case  0: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti0, aasti1, \
							value1, value2); \
		break; \
	case  1: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti1, aasti2, \
							value1, value2); \
		break; \
	case  2: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti2, aasti3, \
							value1, value2); \
		break; \
	case  3: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti3, aasti4, \
							value1, value2);\
		break; \
	case  4: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti4, aasti5, \
							value1, value2); \
		break; \
	case  5: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti5, aasti6, \
							value1, value2); \
		break; \
	case  6: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti6, aasti7, \
							value1, value2); \
		break; \
	case  7: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti7, aasti8, \
							value1, value2); \
		break; \
	case  8: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti8, aasti9, \
							value1, value2); \
		break; \
	case  9: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti9, aasti10, \
							value1, value2); \
		break; \
	case 10: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti10, aasti11, \
							value1, value2); \
		break; \
	case 11: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti11, aasti12, \
							value1, value2); \
		break; \
	case 12: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti12, aasti13, \
							value1, value2); \
		break; \
	case 13: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti13, aasti14, \
							value1, value2); \
		break; \
	case 14: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti14, aasti15, \
							value1, value2); \
		break; \
	case 15: \
		PV_TYPE##_GET_AAU_AASTIS_##ISET(aasti15, aasti_tag, \
							value1, value2); \
		break; \
	default: \
		BUG_AAU(); \
		value1 = 0; \
		value2 = 0; \
	} \
})
#define	NATIVE_READ_AASTIS_PAIR_VALUE_V2(AASTIs_pair, lo_value, hi_value) \
		PREFIX_READ_AASTIS_PAIR_VALUE(NATIVE, native, V2, v2, \
					AASTIs_pair, lo_value, hi_value)
#define	NATIVE_READ_AASTIS_PAIR_VALUE_V5(AASTIs_pair, lo_value, hi_value) \
		PREFIX_READ_AASTIS_PAIR_VALUE(NATIVE, native, V5, v5, \
					AASTIs_pair, lo_value, hi_value)

static __always_inline void
native_write_aastis_pair_value(int AASTIs_pair, u64 lo_value, u64 hi_value)
{
	switch (AASTIs_pair) {
	case  0:
		NATIVE_SET_AAU_AASTIS(aasti0, aasti1, lo_value, hi_value);
		break;
	case  1:
		NATIVE_SET_AAU_AASTIS(aasti1, aasti2, lo_value, hi_value);
		break;
	case  2:
		NATIVE_SET_AAU_AASTIS(aasti2, aasti3, lo_value, hi_value);
		break;
	case  3:
		NATIVE_SET_AAU_AASTIS(aasti3, aasti4, lo_value, hi_value);
		break;
	case  4:
		NATIVE_SET_AAU_AASTIS(aasti4, aasti5, lo_value, hi_value);
		break;
	case  5:
		NATIVE_SET_AAU_AASTIS(aasti5, aasti6, lo_value, hi_value);
		break;
	case  6:
		NATIVE_SET_AAU_AASTIS(aasti6, aasti7, lo_value, hi_value);
		break;
	case  7:
		NATIVE_SET_AAU_AASTIS(aasti7, aasti8, lo_value, hi_value);
		break;
	case  8:
		NATIVE_SET_AAU_AASTIS(aasti8, aasti9, lo_value, hi_value);
		break;
	case  9:
		NATIVE_SET_AAU_AASTIS(aasti9, aasti10, lo_value, hi_value);
		break;
	case 10:
		NATIVE_SET_AAU_AASTIS(aasti10, aasti11, lo_value, hi_value);
		break;
	case 11:
		NATIVE_SET_AAU_AASTIS(aasti11, aasti12, lo_value, hi_value);
		break;
	case 12:
		NATIVE_SET_AAU_AASTIS(aasti12, aasti13, lo_value, hi_value);
		break;
	case 13:
		NATIVE_SET_AAU_AASTIS(aasti13, aasti14, lo_value, hi_value);
		break;
	case 14:
		NATIVE_SET_AAU_AASTIS(aasti14, aasti15, lo_value, hi_value);
		break;
	case 15:
		NATIVE_SET_AAU_AASTIS(aasti15, aasti_tag, lo_value, hi_value);
		break;
	default:
		BUG_AAU();
	}
}

#define	PREFIX_READ_AALDI_REG_VALUE(PV_TYPE, pv_type, ISET, iset, \
					AALDI_no, value1, value2) \
({ \
	switch (AALDI_no) { \
	case  0: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi0, value1, value2); \
		break; \
	case  1: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi1, value1, value2); \
		break; \
	case  2: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi2, value1, value2); \
		break; \
	case  3: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi3, value1, value2); \
		break; \
	case  4: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi4, value1, value2); \
		break; \
	case  5: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi5, value1, value2); \
		break; \
	case  6: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi6, value1, value2); \
		break; \
	case  7: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi7, value1, value2); \
		break; \
	case  8: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi8, value1, value2); \
		break; \
	case  9: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi9, value1, value2); \
		break; \
	case 10: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi10, value1, value2); \
		break; \
	case 11: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi11, value1, value2); \
		break; \
	case 12: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi12, value1, value2); \
		break; \
	case 13: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi13, value1, value2); \
		break; \
	case 14: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi14, value1, value2); \
		break; \
	case 15: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi15, value1, value2); \
		break; \
	case 16: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi16, value1, value2); \
		break; \
	case 17: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi17, value1, value2); \
		break; \
	case 18: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi18, value1, value2); \
		break; \
	case 19: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi19, value1, value2); \
		break; \
	case 20: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi20, value1, value2); \
		break; \
	case 21: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi21, value1, value2); \
		break; \
	case 22: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi22, value1, value2); \
		break; \
	case 23: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi23, value1, value2); \
		break; \
	case 24: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi24, value1, value2); \
		break; \
	case 25: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi25, value1, value2); \
		break; \
	case 26: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi26, value1, value2); \
		break; \
	case 27: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi27, value1, value2); \
		break; \
	case 28: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi28, value1, value2); \
		break; \
	case 29: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi29, value1, value2); \
		break; \
	case 30: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi30, value1, value2); \
		break; \
	case 31: \
		PV_TYPE##_GET_AAU_AALDI_##ISET(aaldi31, value1, value2); \
		break; \
	default: \
		BUG_AAU(); \
		value1 = 0; \
		value2 = 0; \
	} \
})
#define	NATIVE_READ_AALDI_REG_VALUE_V2(AALDI_no, value1, value2) \
		PREFIX_READ_AALDI_REG_VALUE(NATIVE, native, V2, v2, \
					AALDI_no, value1, value2)
#define	NATIVE_READ_AALDI_REG_VALUE_V5(AALDI_no, value1, value2) \
		PREFIX_READ_AALDI_REG_VALUE(NATIVE, native, V5, v5, \
					AALDI_no, value1, value2)

static inline void
native_read_aaldi_reg_value_v2(int AALDI_no, u64 *l_value, u64 *r_value)
{
	u32 value1, value2;

	NATIVE_READ_AALDI_REG_VALUE_V2(AALDI_no, value1, value2);
	*l_value = value1;
	*r_value = value2;
}

static inline void
native_read_aaldi_reg_value_v5(int AALDI_no, u64 *l_value, u64 *r_value)
{
	u64 value1, value2;

	NATIVE_READ_AALDI_REG_VALUE_V5(AALDI_no, value1, value2);
	*l_value = value1;
	*r_value = value2;
}

static inline void
native_write_aaldi_reg_value(int AALDI_no, u64 l_value, u64 r_value)
{
	switch (AALDI_no) {
	case  0:
		NATIVE_SET_AAU_AALDI(aaldi0, l_value, r_value);
		break;
	case  1:
		NATIVE_SET_AAU_AALDI(aaldi1, l_value, r_value);
		break;
	case  2:
		NATIVE_SET_AAU_AALDI(aaldi2, l_value, r_value);
		break;
	case  3:
		NATIVE_SET_AAU_AALDI(aaldi3, l_value, r_value);
		break;
	case  4:
		NATIVE_SET_AAU_AALDI(aaldi4, l_value, r_value);
		break;
	case  5:
		NATIVE_SET_AAU_AALDI(aaldi5, l_value, r_value);
		break;
	case  6:
		NATIVE_SET_AAU_AALDI(aaldi6, l_value, r_value);
		break;
	case  7:
		NATIVE_SET_AAU_AALDI(aaldi7, l_value, r_value);
		break;
	case  8:
		NATIVE_SET_AAU_AALDI(aaldi8, l_value, r_value);
		break;
	case  9:
		NATIVE_SET_AAU_AALDI(aaldi9, l_value, r_value);
		break;
	case 10:
		NATIVE_SET_AAU_AALDI(aaldi10, l_value, r_value);
		break;
	case 11:
		NATIVE_SET_AAU_AALDI(aaldi11, l_value, r_value);
		break;
	case 12:
		NATIVE_SET_AAU_AALDI(aaldi12, l_value, r_value);
		break;
	case 13:
		NATIVE_SET_AAU_AALDI(aaldi13, l_value, r_value);
		break;
	case 14:
		NATIVE_SET_AAU_AALDI(aaldi14, l_value, r_value);
		break;
	case 15:
		NATIVE_SET_AAU_AALDI(aaldi15, l_value, r_value);
		break;
	case 16:
		NATIVE_SET_AAU_AALDI(aaldi16, l_value, r_value);
		break;
	case 17:
		NATIVE_SET_AAU_AALDI(aaldi17, l_value, r_value);
		break;
	case 18:
		NATIVE_SET_AAU_AALDI(aaldi18, l_value, r_value);
		break;
	case 19:
		NATIVE_SET_AAU_AALDI(aaldi19, l_value, r_value);
		break;
	case 20:
		NATIVE_SET_AAU_AALDI(aaldi20, l_value, r_value);
		break;
	case 21:
		NATIVE_SET_AAU_AALDI(aaldi21, l_value, r_value);
		break;
	case 22:
		NATIVE_SET_AAU_AALDI(aaldi22, l_value, r_value);
		break;
	case 23:
		NATIVE_SET_AAU_AALDI(aaldi23, l_value, r_value);
		break;
	case 24:
		NATIVE_SET_AAU_AALDI(aaldi24, l_value, r_value);
		break;
	case 25:
		NATIVE_SET_AAU_AALDI(aaldi25, l_value, r_value);
		break;
	case 26:
		NATIVE_SET_AAU_AALDI(aaldi26, l_value, r_value);
		break;
	case 27:
		NATIVE_SET_AAU_AALDI(aaldi27, l_value, r_value);
		break;
	case 28:
		NATIVE_SET_AAU_AALDI(aaldi28, l_value, r_value);
		break;
	case 29:
		NATIVE_SET_AAU_AALDI(aaldi29, l_value, r_value);
		break;
	case 30:
		NATIVE_SET_AAU_AALDI(aaldi30, l_value, r_value);
		break;
	case 31:
		NATIVE_SET_AAU_AALDI(aaldi31, l_value, r_value);
		break;
	default:
		BUG_AAU();
		l_value = 0;
		r_value = 0;
	}
}

#define	PREFIX_READ_AALDAS_REG_VALUE(PV_TYPE, pv_type, \
					AALDAs_no, value1, value2) \
({ \
	switch (AALDAs_no) { \
	case  0: \
		PV_TYPE##_GET_AAU_AALDA(aalda0, value1, value2); \
		break; \
	case  4: \
		PV_TYPE##_GET_AAU_AALDA(aalda4, value1, value2); \
		break; \
	case  8: \
		PV_TYPE##_GET_AAU_AALDA(aalda8, value1, value2); \
		break; \
	case 12: \
		PV_TYPE##_GET_AAU_AALDA(aalda12, value1, value2); \
		break; \
	case 16: \
		PV_TYPE##_GET_AAU_AALDA(aalda16, value1, value2); \
		break; \
	case 20: \
		PV_TYPE##_GET_AAU_AALDA(aalda20, value1, value2); \
		break; \
	case 24: \
		PV_TYPE##_GET_AAU_AALDA(aalda24, value1, value2); \
		break; \
	case 28: \
		PV_TYPE##_GET_AAU_AALDA(aalda28, value1, value2); \
		break; \
	default: \
		BUG_AAU(); \
		value1 = 0; \
		value2 = 0; \
	} \
})
#define	NATIVE_READ_AALDAS_REG_VALUE(AALDAs_no, value1, value2) \
		PREFIX_READ_AALDAS_REG_VALUE(NATIVE, native, \
					AALDAs_no, value1, value2)

static inline void
native_read_aaldas_reg_value(int AALDAs_no, u32 *l_value, u32 *r_value)
{
	u32 value1, value2;

	NATIVE_READ_AALDAS_REG_VALUE(AALDAs_no, value1, value2);
	*l_value = value1;
	*r_value = value2;
}

static inline void
native_write_aaldas_reg_value(int AALDAs_no, u32 l_value, u32 r_value)
{
	switch (AALDAs_no) {
	case  0:
		NATIVE_SET_AAU_AALDA(aalda0, l_value, r_value);
		break;
	case  4:
		NATIVE_SET_AAU_AALDA(aalda4, l_value, r_value);
		break;
	case  8:
		NATIVE_SET_AAU_AALDA(aalda8, l_value, r_value);
		break;
	case 12:
		NATIVE_SET_AAU_AALDA(aalda12, l_value, r_value);
		break;
	case 16:
		NATIVE_SET_AAU_AALDA(aalda16, l_value, r_value);
		break;
	case 20:
		NATIVE_SET_AAU_AALDA(aalda20, l_value, r_value);
		break;
	case 24:
		NATIVE_SET_AAU_AALDA(aalda24, l_value, r_value);
		break;
	case 28:
		NATIVE_SET_AAU_AALDA(aalda28, l_value, r_value);
		break;
	default:
		BUG_AAU();
		l_value = 0;
		r_value = 0;
	}
}
static inline void native_read_aaldm_reg_value(u32 *lo_value, u32 *hi_value)
{
	u32 value1, value2;

	NATIVE_GET_AAU_AALDM(value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
static __always_inline void native_write_aaldm_reg_value(u32 lo_value,
						u32 hi_value)
{
	NATIVE_SET_AAU_AALDM(lo_value, hi_value);
}
static inline void native_read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	native_read_aaldm_reg_value(&aaldm->lo, &aaldm->hi);
}
static __always_inline void native_write_aaldm_reg(e2k_aaldm_t *aaldm)
{
	native_write_aaldm_reg_value(aaldm->lo, aaldm->hi);
}
static inline void native_read_aaldv_reg_value(u32 *lo_value, u32 *hi_value)
{
	u32 value1, value2;

	NATIVE_GET_AAU_AALDV(value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
static __always_inline void native_write_aaldv_reg_value(u32 lo_value,
						u32 hi_value)
{
	NATIVE_SET_AAU_AALDV(lo_value, hi_value);
}
static inline void native_read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	native_read_aaldv_reg_value(&aaldv->lo, &aaldv->hi);
}
static __always_inline void native_write_aaldv_reg(e2k_aaldv_t *aaldv)
{
	native_write_aaldv_reg_value(aaldv->lo, aaldv->hi);
}

static inline void native_read_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	switch (AAD_no) {
	case  0:
		NATIVE_GET_AAU_AAD(aadr0, mem_p);
		break;
	case  1:
		NATIVE_GET_AAU_AAD(aadr1, mem_p);
		break;
	case  2:
		NATIVE_GET_AAU_AAD(aadr2, mem_p);
		break;
	case  3:
		NATIVE_GET_AAU_AAD(aadr3, mem_p);
		break;
	case  4:
		NATIVE_GET_AAU_AAD(aadr4, mem_p);
		break;
	case  5:
		NATIVE_GET_AAU_AAD(aadr5, mem_p);
		break;
	case  6:
		NATIVE_GET_AAU_AAD(aadr6, mem_p);
		break;
	case  7:
		NATIVE_GET_AAU_AAD(aadr7, mem_p);
		break;
	case  8:
		NATIVE_GET_AAU_AAD(aadr8, mem_p);
		break;
	case  9:
		NATIVE_GET_AAU_AAD(aadr9, mem_p);
		break;
	case 10:
		NATIVE_GET_AAU_AAD(aadr10, mem_p);
		break;
	case 11:
		NATIVE_GET_AAU_AAD(aadr11, mem_p);
		break;
	case 12:
		NATIVE_GET_AAU_AAD(aadr12, mem_p);
		break;
	case 13:
		NATIVE_GET_AAU_AAD(aadr13, mem_p);
		break;
	case 14:
		NATIVE_GET_AAU_AAD(aadr14, mem_p);
		break;
	case 15:
		NATIVE_GET_AAU_AAD(aadr15, mem_p);
		break;
	case 16:
		NATIVE_GET_AAU_AAD(aadr16, mem_p);
		break;
	case 17:
		NATIVE_GET_AAU_AAD(aadr17, mem_p);
		break;
	case 18:
		NATIVE_GET_AAU_AAD(aadr18, mem_p);
		break;
	case 19:
		NATIVE_GET_AAU_AAD(aadr19, mem_p);
		break;
	case 20:
		NATIVE_GET_AAU_AAD(aadr20, mem_p);
		break;
	case 21:
		NATIVE_GET_AAU_AAD(aadr21, mem_p);
		break;
	case 22:
		NATIVE_GET_AAU_AAD(aadr22, mem_p);
		break;
	case 23:
		NATIVE_GET_AAU_AAD(aadr23, mem_p);
		break;
	case 24:
		NATIVE_GET_AAU_AAD(aadr24, mem_p);
		break;
	case 25:
		NATIVE_GET_AAU_AAD(aadr25, mem_p);
		break;
	case 26:
		NATIVE_GET_AAU_AAD(aadr26, mem_p);
		break;
	case 27:
		NATIVE_GET_AAU_AAD(aadr27, mem_p);
		break;
	case 28:
		NATIVE_GET_AAU_AAD(aadr28, mem_p);
		break;
	case 29:
		NATIVE_GET_AAU_AAD(aadr29, mem_p);
		break;
	case 30:
		NATIVE_GET_AAU_AAD(aadr30, mem_p);
		break;
	case 31:
		NATIVE_GET_AAU_AAD(aadr31, mem_p);
		break;
	default:
		BUG_AAU();
	}
}

static inline void native_write_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	switch (AAD_no) {
	case  0:
		NATIVE_SET_AAU_AAD(aadr0, mem_p);
		break;
	case  1:
		NATIVE_SET_AAU_AAD(aadr1, mem_p);
		break;
	case  2:
		NATIVE_SET_AAU_AAD(aadr2, mem_p);
		break;
	case  3:
		NATIVE_SET_AAU_AAD(aadr3, mem_p);
		break;
	case  4:
		NATIVE_SET_AAU_AAD(aadr4, mem_p);
		break;
	case  5:
		NATIVE_SET_AAU_AAD(aadr5, mem_p);
		break;
	case  6:
		NATIVE_SET_AAU_AAD(aadr6, mem_p);
		break;
	case  7:
		NATIVE_SET_AAU_AAD(aadr7, mem_p);
		break;
	case  8:
		NATIVE_SET_AAU_AAD(aadr8, mem_p);
		break;
	case  9:
		NATIVE_SET_AAU_AAD(aadr9, mem_p);
		break;
	case 10:
		NATIVE_SET_AAU_AAD(aadr10, mem_p);
		break;
	case 11:
		NATIVE_SET_AAU_AAD(aadr11, mem_p);
		break;
	case 12:
		NATIVE_SET_AAU_AAD(aadr12, mem_p);
		break;
	case 13:
		NATIVE_SET_AAU_AAD(aadr13, mem_p);
		break;
	case 14:
		NATIVE_SET_AAU_AAD(aadr14, mem_p);
		break;
	case 15:
		NATIVE_SET_AAU_AAD(aadr15, mem_p);
		break;
	case 16:
		NATIVE_SET_AAU_AAD(aadr16, mem_p);
		break;
	case 17:
		NATIVE_SET_AAU_AAD(aadr17, mem_p);
		break;
	case 18:
		NATIVE_SET_AAU_AAD(aadr18, mem_p);
		break;
	case 19:
		NATIVE_SET_AAU_AAD(aadr19, mem_p);
		break;
	case 20:
		NATIVE_SET_AAU_AAD(aadr20, mem_p);
		break;
	case 21:
		NATIVE_SET_AAU_AAD(aadr21, mem_p);
		break;
	case 22:
		NATIVE_SET_AAU_AAD(aadr22, mem_p);
		break;
	case 23:
		NATIVE_SET_AAU_AAD(aadr23, mem_p);
		break;
	case 24:
		NATIVE_SET_AAU_AAD(aadr24, mem_p);
		break;
	case 25:
		NATIVE_SET_AAU_AAD(aadr25, mem_p);
		break;
	case 26:
		NATIVE_SET_AAU_AAD(aadr26, mem_p);
		break;
	case 27:
		NATIVE_SET_AAU_AAD(aadr27, mem_p);
		break;
	case 28:
		NATIVE_SET_AAU_AAD(aadr28, mem_p);
		break;
	case 29:
		NATIVE_SET_AAU_AAD(aadr29, mem_p);
		break;
	case 30:
		NATIVE_SET_AAU_AAD(aadr30, mem_p);
		break;
	case 31:
		NATIVE_SET_AAU_AAD(aadr31, mem_p);
		break;
	default:
		BUG_AAU();
	}
}

static __always_inline void native_read_aads_4_reg(int AADs_no, e2k_aadj_t *mem_p)
{
	switch (AADs_no) {
	case  0:
		NATIVE_GET_AAU_AADS(aadr0, aadr1, aadr2, aadr3, mem_p);
		break;
	case  4:
		NATIVE_GET_AAU_AADS(aadr4, aadr5, aadr6, aadr7, mem_p);
		break;
	case  8:
		NATIVE_GET_AAU_AADS(aadr8, aadr9, aadr10, aadr11, mem_p);
		break;
	case 12:
		NATIVE_GET_AAU_AADS(aadr12, aadr13, aadr14, aadr15, mem_p);
		break;
	case 16:
		NATIVE_GET_AAU_AADS(aadr16, aadr17, aadr18, aadr19, mem_p);
		break;
	case 20:
		NATIVE_GET_AAU_AADS(aadr20, aadr21, aadr22, aadr23, mem_p);
		break;
	case 24:
		NATIVE_GET_AAU_AADS(aadr24, aadr25, aadr26, aadr27, mem_p);
		break;
	case 28:
		NATIVE_GET_AAU_AADS(aadr28, aadr29, aadr30, aadr31, mem_p);
		break;
	default:
		BUG_AAU();
	}
}

static __always_inline void native_write_aads_4_reg(int AADs_no,
						e2k_aadj_t *mem_p)
{
	switch (AADs_no) {
	case  0:
		NATIVE_SET_AAU_AADS(aadr0, aadr1, aadr2, aadr3, mem_p);
		break;
	case  4:
		NATIVE_SET_AAU_AADS(aadr4, aadr5, aadr6, aadr7, mem_p);
		break;
	case  8:
		NATIVE_SET_AAU_AADS(aadr8, aadr9, aadr10, aadr11, mem_p);
		break;
	case 12:
		NATIVE_SET_AAU_AADS(aadr12, aadr13, aadr14, aadr15, mem_p);
		break;
	case 16:
		NATIVE_SET_AAU_AADS(aadr16, aadr17, aadr18, aadr19, mem_p);
		break;
	case 20:
		NATIVE_SET_AAU_AADS(aadr20, aadr21, aadr22, aadr23, mem_p);
		break;
	case 24:
		NATIVE_SET_AAU_AADS(aadr24, aadr25, aadr26, aadr27, mem_p);
		break;
	case 28:
		NATIVE_SET_AAU_AADS(aadr28, aadr29, aadr30, aadr31, mem_p);
		break;
	default:
		BUG_AAU();
	}
}

/* Clear AAU to prepare it for restoring.
 * Make this a macro to avoid include hell - it uses cpu_has() inside... */
#define native_clear_apb() NATIVE_CLEAR_APB()

#endif /* _NATIVE_AAU_REGS_ACCESS_H_ */
