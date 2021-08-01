/*
 * KVM AAU registers model access
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

#ifndef _KVM_AAU_REGS_ACCESS_H_
#define _KVM_AAU_REGS_ACCESS_H_

#include <linux/types.h>
#include <asm/aau_regs_types.h>
#include <asm/kvm/guest.h>

/*
 * Basic functions accessing virtual AAUs registers on guest.
 */
#define	GUEST_AAU_REGS_BASE	offsetof(kvm_vcpu_state_t, cpu.aau)
#define	GUEST_AAU_REG(reg_name) (GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, reg_name)))
#define	GUEST_AAU_AAIND(AAIND_no) (GUEST_AAU_REGS_BASE +		\
				(offsetof(e2k_aau_t, aainds)) +	\
				(sizeof(u64) * (AAIND_no)))
#define	GUEST_AAU_AAINCR(AAINCR_no) (GUEST_AAU_REGS_BASE +		\
				(offsetof(e2k_aau_t, aaincrs)) +	\
				(sizeof(u64) * (AAINCR_no)))
#define	GUEST_AAU_AASTI(AASTI_no) (GUEST_AAU_REGS_BASE +		\
				(offsetof(e2k_aau_t, aastis)) +	\
				(sizeof(u64) * (AASTI_no)))
#define	GUEST_AAU_AALDI(AALDI_no) (offsetof(kvm_vcpu_state_t, cpu.aaldi) + \
				(sizeof(u64) * (AALDI_no)))
#define	GUEST_AAU_AALDA(AALDA_no) (offsetof(kvm_vcpu_state_t, cpu.aalda) + \
				(sizeof(e2k_aalda_t) * (AALDA_no)))
#define	GUEST_AAU_AAD_lo(AAD_no) (GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aads)) +		\
				(sizeof(e2k_aadj_t) * (AAD_no)) +	\
				(offsetof(e2k_aadj_t, word.lo)))
#define	GUEST_AAU_AAD_hi(AAD_no) (GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aads)) +		\
				(sizeof(e2k_aadj_t) * (AAD_no)) +	\
				(offsetof(e2k_aadj_t, word.hi)))
#define	GUEST_AAU_AALDM_lo()	(GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aaldm)) +		\
				(offsetof(e2k_aaldm_t, lo)))
#define	GUEST_AAU_AALDM_hi()	(GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aaldm)) +		\
				(offsetof(e2k_aaldm_t, hi)))
#define	GUEST_AAU_AALDV_lo()	(GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aaldv)) +		\
				(offsetof(e2k_aaldv_t, lo)))
#define	GUEST_AAU_AALDV_hi()	(GUEST_AAU_REGS_BASE +			\
				(offsetof(e2k_aau_t, aaldv)) +		\
				(offsetof(e2k_aaldv_t, hi)))
#define	GUEST_GET_AAU_BREG(reg_name)					\
		E2K_LOAD_GUEST_VCPU_STATE_B(GUEST_AAU_REG(reg_name))
#define	GUEST_GET_AAU_SREG(reg_name)					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_REG(reg_name))
#define	GUEST_GET_AAU_DREG(reg_name)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_REG(reg_name))
#define	GUEST_SET_AAU_BREG(reg_name, value)				\
		E2K_STORE_GUEST_VCPU_STATE_B(GUEST_AAU_REG(reg_name), value)
#define	GUEST_SET_AAU_SREG(reg_name, value)				\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_REG(reg_name), value)
#define	GUEST_SET_AAU_DREG(reg_name, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_REG(reg_name), value)
#define	GUEST_GET_AAU_AAIND(AAIND_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AAIND(AAIND_no))
#define	GUEST_GET_AAU_AAINCR(AAINCR_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AAINCR(AAINCR_no))
#define	GUEST_GET_AAU_AASTI(AASTI_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AASTI(AASTI_no))
#define	GUEST_GET_AAU_AALDI(AALDI_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AALDI(AALDI_no))
#define	GUEST_GET_AAU_AALDA(AALDA_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_AALDA(AALDA_no))
#define	GUEST_GET_AAU_AAD_lo(AAD_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AAD_lo(AAD_no))
#define	GUEST_GET_AAU_AAD_hi(AAD_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_AAU_AAD_hi(AAD_no))
#define	GUEST_GET_AAU_AAD(AAD_no, mem_p)				\
({									\
	AWP(mem_p).lo = GUEST_GET_AAU_AAD_lo(AAD_no);			\
	AWP(mem_p).hi = GUEST_GET_AAU_AAD_hi(AAD_no);			\
})
#define	GUEST_GET_AAU_AALDM_lo()					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_AALDM_lo())
#define	GUEST_GET_AAU_AALDM_hi()					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_AALDM_hi())
#define	GUEST_GET_AAU_AALDV_lo()					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_AALDV_lo())
#define	GUEST_GET_AAU_AALDV_hi()					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_AAU_AALDV_hi())

#define	GUEST_SET_AAU_AAIND(AAIND_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AAIND(AAIND_no), value)
#define	GUEST_SET_AAU_AAINCR(AAINCR_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AAINCR(AAINCR_no), value)
#define	GUEST_SET_AAU_AASTI(AASTI_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AASTI(AASTI_no), value)
#define	GUEST_SET_AAU_AALDI(AALDI_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AALDI(AALDI_no), value)
#define	GUEST_SET_AAU_AALDA(AALDA_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_AALDI(AALDA_no), value)
#define	GUEST_SET_AAU_AAD_lo(AAD_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AAD_lo(AAD_no), value)
#define	GUEST_SET_AAU_AAD_hi(AAD_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_AAU_AAD_hi(AAD_no), value)
#define	GUEST_SET_AAU_AAD(AAD_no, mem_p)				\
({									\
	GUEST_SET_AAU_AAD_lo(AAD_no, AWP(mem_p).lo);			\
	GUEST_SET_AAU_AAD_hi(AAD_no, AWP(mem_p).hi);			\
})
#define	GUEST_SET_AAU_AALDM_lo(lo)					\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_AALDM_lo(), lo)
#define	GUEST_SET_AAU_AALDM_hi(hi)					\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_AALDM_hi(), hi)
#define	GUEST_SET_AAU_AALDV_lo(lo)					\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_AALDV_lo(), lo)
#define	GUEST_SET_AAU_AALDV_hi(hi)					\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_AAU_AALDV_hi(), hi)

/* macros to deal with KVM AAU registers model */

#define KVM_GET_AAU_AAD(AAD_no, mem_p)					\
		GUEST_GET_AAU_AAD(AAD_no, (mem_p))
#define KVM_GET_AAU_4_AADs(AAD_4_no, mem_4_p)				\
({									\
	KVM_GET_AAU_AAD(((AAD_4_no) + 0), &(mem_4_p)[0]);		\
	KVM_GET_AAU_AAD(((AAD_4_no) + 1), &(mem_4_p)[1]);		\
	KVM_GET_AAU_AAD(((AAD_4_no) + 2), &(mem_4_p)[2]);		\
	KVM_GET_AAU_AAD(((AAD_4_no) + 3), &(mem_4_p)[3]);		\
})
#define KVM_GET_AAU_AAIND(AAIND_no)					\
		GUEST_GET_AAU_AAIND(AAIND_no)
#define KVM_GET_AAU_AAINDS_VAL(AAIND1_no, AAIND2_no, val1, val2)	\
({									\
	val1 = GUEST_GET_AAU_AAIND(AAIND1_no);				\
	val2 = GUEST_GET_AAU_AAIND(AAIND2_no);				\
})
#define KVM_GET_AAU_AAIND_TAG()						\
		GUEST_GET_AAU_SREG(aaind_tags)
#define KVM_GET_AAU_AAINDS(AAIND1_no, AAIND2_no, val1, val2)		\
({									\
	if (((AAIND1_no) != AAINDS_TAG_no) &&				\
			((AAIND2_no) != AAINDS_TAG_no)) {		\
		KVM_GET_AAU_AAINDS_VAL(AAIND1_no, AAIND2_no, val1, val2); \
	} else if ((AAIND1_no) == AAINDS_TAG_no) {			\
		val1 = KVM_GET_AAU_AAIND_TAG();				\
		val2 = GUEST_GET_AAU_AAIND(AAIND2_no);			\
	} else {							\
		val1 = GUEST_GET_AAU_AAIND(AAIND1_no);			\
		val2 = KVM_GET_AAU_AAIND_TAG();				\
	}								\
})
#define KVM_GET_AAU_AAINCR(AAINCR_no)					\
		GUEST_GET_AAU_AAINCR(AAINCR_no)
#define KVM_GET_AAU_AAINCRS_VAL(AAINCR1_no, AAINCR2_no, val1, val2)	\
({									\
	val1 = GUEST_GET_AAU_AAINCR(AAINCR1_no);			\
	val2 = GUEST_GET_AAU_AAINCR(AAINCR2_no);			\
})
#define KVM_GET_AAU_AAINCR_TAG()					\
		GUEST_GET_AAU_SREG(aaincr_tags)
#define KVM_GET_AAU_AAINCRS(AAINCR1_no, AAINCR2_no, val1, val2)		\
({									\
	if (((AAINCR1_no) != AAINCRS_TAG_no) &&				\
			((AAINCR2_no) != AAINCRS_TAG_no)) {		\
		KVM_GET_AAU_AAINCRS_VAL(AAINCR1_no, AAINCR2_no, val1, val2); \
	} else if ((AAINCR1_no) == AAINCRS_TAG_no) {			\
		val1 = KVM_GET_AAU_AAINCR_TAG();			\
		val2 = GUEST_GET_AAU_AAINCR(AAINCR2_no);		\
	} else {							\
		val1 = GUEST_GET_AAU_AAINCR(AAINCR1_no);		\
		val2 = KVM_GET_AAU_AAINCR_TAG();			\
	}								\
})
#define KVM_GET_AAU_AASTI(AASTI_no)					\
		GUEST_GET_AAU_AASTI(AASTI_no)
#define KVM_GET_AAU_AASTIS(AASTI1_no, AASTI2_no, val1, val2)		\
({									\
	val1 = GUEST_GET_AAU_AASTI(AASTI1_no);				\
	val2 = GUEST_GET_AAU_AASTI(AASTI2_no);				\
})
#define KVM_GET_AAU_AASTI_TAG()						\
		GUEST_GET_AAU_SREG(aasti_tags)
#define KVM_GET_AAU_AASR()						\
		GUEST_GET_AAU_SREG(aasr)
#define KVM_GET_AAU_AAFSTR()						\
		GUEST_GET_AAU_SREG(aafstr)
#define KVM_GET_AAU_AALDI(AALDI_no, lval, rval)				\
({									\
	lval = GUEST_GET_AAU_AALDI(((AALDI_no) +  0));			\
	rval = GUEST_GET_AAU_AALDI(((AALDI_no) + 32));			\
})
#define KVM_GET_AAU_AALDA(AALDA_no, lval, rval)				\
({									\
	lval = GUEST_GET_AAU_AALDA((AALDA_no) +  0);			\
	rval = GUEST_GET_AAU_AALDA((AALDA_no) + 32);			\
})
#define KVM_GET_AAU_AALDM_lo()		GUEST_GET_AAU_AALDM_lo()
#define KVM_GET_AAU_AALDM_hi()		GUEST_GET_AAU_AALDM_hi()
#define KVM_GET_AAU_AALDM(lo, hi)					\
({									\
	lo = KVM_GET_AAU_AALDM_lo();					\
	hi = KVM_GET_AAU_AALDM_hi();					\
})
#define KVM_GET_AAU_AALDV_lo()		GUEST_GET_AAU_AALDV_lo()
#define KVM_GET_AAU_AALDV_hi()		GUEST_GET_AAU_AALDV_hi()
#define KVM_GET_AAU_AALDV(lo, hi)					\
({									\
	lo = KVM_GET_AAU_AALDV_lo();					\
	hi = KVM_GET_AAU_AALDV_hi();					\
})

#define KVM_SET_AAU_AAD(AAD_no, mem_p)					\
		GUEST_SET_AAU_AAD(AAD_no, (mem_p))
#define KVM_SET_AAU_4_AADs(AAD_4_no, mem_4_p)				\
({									\
	KVM_SET_AAU_AAD(((AAD_4_no) + 0), &(mem_4_p)[0]);		\
	KVM_SET_AAU_AAD(((AAD_4_no) + 1), &(mem_4_p)[1]);		\
	KVM_SET_AAU_AAD(((AAD_4_no) + 2), &(mem_4_p)[2]);		\
	KVM_SET_AAU_AAD(((AAD_4_no) + 3), &(mem_4_p)[3]);		\
})
#define KVM_SET_AAU_AAIND(AAIND_no, value)				\
		GUEST_SET_AAU_AAIND(AAIND_no, value)
#define KVM_SET_AAU_AAINDS_VAL(AAIND1_no, AAIND2_no, val1, val2)	\
({									\
	GUEST_SET_AAU_AAIND(AAIND1_no, val1);				\
	GUEST_SET_AAU_AAIND(AAIND2_no, val2);				\
})
#define KVM_SET_AAU_AAIND_TAG(val)					\
		GUEST_SET_AAU_SREG(aaind_tags, val)
#define KVM_SET_AAU_AAINDS(AAIND1_no, AAIND2_no, val1, val2)		\
({									\
	if (((AAIND1_no) != AAINDS_TAG_no) &&				\
			((AAIND2_no) != AAINDS_TAG_no)) {		\
		KVM_SET_AAU_AAINDS_VAL(AAIND1_no, AAIND2_no, val1, val2); \
	} else if ((AAIND1_no) == AAINDS_TAG_no) {			\
		KVM_SET_AAU_AAIND_TAG(val1);				\
		GUEST_SET_AAU_AAIND(AAIND2_no, val2);			\
	} else {							\
		GUEST_SET_AAU_AAIND(AAIND1_no, val1);			\
		KVM_SET_AAU_AAIND_TAG(val2);				\
	}								\
})
#define KVM_SET_AAU_AAINCR(AAINCR_no, val)				\
		GUEST_SET_AAU_AAINCR(AAINCR_no, val)
#define KVM_SET_AAU_AAINCRS_VAL(AAINCR1_no, AAINCR2_no, val1, val2)	\
({									\
	GUEST_SET_AAU_AAINCR(AAINCR1_no, val1);				\
	GUEST_SET_AAU_AAINCR(AAINCR2_no, val2);				\
})
#define KVM_SET_AAU_AAINCR_TAG(val)					\
		GUEST_SET_AAU_SREG(aaincr_tags, val)
#define KVM_SET_AAU_AAIND_AAINCR_TAGS(aaind, aaincr) \
do { \
	GUEST_SET_AAU_SREG(aaincr_tags, aaincr); \
	GUEST_SET_AAU_SREG(aaind_tags, aaind); \
} while (0)

#define KVM_SET_AAU_AAINCRS(AAINCR1_no, AAINCR2_no, val1, val2)		\
({									\
	if (((AAINCR1_no) != AAINCRS_TAG_no) &&				\
			((AAINCR2_no) != AAINCRS_TAG_no)) {		\
		KVM_SET_AAU_AAINCRS_VAL(AAINCR1_no, AAINCR2_no, val1, val2); \
	} else if ((AAINCR1_no) == AAINCRS_TAG_no) {			\
		KVM_SET_AAU_AAINCR_TAG(val1);				\
		GUEST_SET_AAU_AAINCR(AAINCR2_no, val2);			\
	} else {							\
		GUEST_SET_AAU_AAINCR(AAINCR1_no, val1);			\
		KVM_SET_AAU_AAINCR_TAG(val2);				\
	}								\
})
#define KVM_SET_AAU_AASTI(AASTI_no, val)				\
		GUEST_SET_AAU_AASTI(AASTI_no, val)
#define KVM_SET_AAU_AASTIS(AASTI1_no, AASTI2_no, val1, val2)		\
({									\
	GUEST_SET_AAU_AASTI(AASTI1_no, val1);				\
	GUEST_SET_AAU_AASTI(AASTI2_no, val2);				\
})
#define KVM_SET_AAU_AASTI_TAG(val)					\
		GUEST_SET_AAU_SREG(aasti_tags, val)
#define KVM_SET_AAU_AASR(val)						\
		GUEST_SET_AAU_SREG(aasr, val)
#define KVM_SET_AAU_AAFSTR(val)						\
		GUEST_SET_AAU_SREG(aafstr, val)
#define KVM_SET_AAU_AALDI(AALDI_no, lval, rval)				\
({									\
	GUEST_SET_AAU_AALDI(((AALDI_no) +  0), lval);			\
	GUEST_SET_AAU_AALDI(((AALDI_no) + 32), rval);			\
})
#define KVM_SET_AAU_AALDA(AALDA_no, lval, rval)				\
({									\
	GUEST_SET_AAU_AALDA(((AALDA_no) +  0), lval);			\
	GUEST_SET_AAU_AALDA(((AALDA_no) + 32), rval);			\
})
#define KVM_SET_AAU_AALDM(lo, hi)					\
({									\
	GUEST_SET_AAU_AALDM_lo(lo);					\
	GUEST_SET_AAU_AALDM_hi(hi);					\
})
#define KVM_SET_AAU_AALDV(lo, hi)					\
({									\
	GUEST_SET_AAU_AALDV_lo(lo);					\
	GUEST_SET_AAU_AALDV_hi(hi);					\
})

/*
 * KVM virtual AAU registers access function (can be paravirtualized)
 */
static __always_inline u32
kvm_read_aasr_reg_value(void)
{
	return KVM_GET_AAU_AASR();
}
static __always_inline void
kvm_write_aasr_reg_value(u32 reg_value)
{
	KVM_SET_AAU_AASR(reg_value);
}
static inline u32
kvm_read_aafstr_reg_value(void)
{
	return KVM_GET_AAU_AAFSTR();
}
static inline void
kvm_write_aafstr_reg_value(u32 reg_value)
{
	KVM_SET_AAU_AAFSTR(reg_value);
}

static __always_inline e2k_aasr_t
kvm_read_aasr_reg(void)
{
	e2k_aasr_t aasr;

	AW(aasr) = kvm_read_aasr_reg_value();
	return aasr;
}
static __always_inline void
kvm_write_aasr_reg(e2k_aasr_t aasr)
{
	kvm_write_aafstr_reg_value(AW(aasr));
}

static inline u64
kvm_read_aaind_reg_value(int AAIND_no)
{
	return KVM_GET_AAU_AAIND(AAIND_no);
}
static inline void
kvm_write_aaind_reg_value(int AAIND_no, u64 reg_value)
{
	KVM_SET_AAU_AAIND(AAIND_no, reg_value);
}

static inline void
kvm_read_aainds_pair_value(int AAINDs_pair, u64 *lo_value, u64 *hi_value)
{
	u64 value1, value2;

	KVM_GET_AAU_AAINDS(AAINDs_pair, (AAINDs_pair + 1), value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
#define	KVM_READ_AAINDS_PAIR_VALUE_V2(AAINDs_pair, value1, value2)	\
		KVM_GET_AAU_AAINDS(AAINDs_pair, ((AAINDs_pair) + 1),	\
					value1, value2)
#define	KVM_READ_AAINDS_PAIR_VALUE_V5(AAINDs_pair, value1, value2)	\
		KVM_GET_AAU_AAINDS(AAINDs_pair, ((AAINDs_pair) + 1),	\
					value1, value2)
#define	KVM_READ_AAIND_REG15_AND_TAGS_VALUE_V5(value15, tags)	\
({ \
	value15 = kvm_read_aaind_reg_value(15);  \
	tags = kvm_read_aaind_tags_reg_value(); \
})

static inline void
kvm_write_aainds_pair_value(int AAINDs_pair, u64 lo_value, u64 hi_value)
{
	KVM_SET_AAU_AAINDS(AAINDs_pair, (AAINDs_pair + 1), lo_value, hi_value);
}
#define	KVM_WRITE_AAINDS_PAIR_VALUE_V2(AAINDs_pair, lo_value, hi_value)	\
		kvm_write_aainds_pair_value(AAINDs_pair, lo_value, hi_value)
#define	KVM_WRITE_AAINDS_PAIR_VALUE_V5(AAINDs_pair, lo_value, hi_value)	\
		kvm_write_aainds_pair_value(AAINDs_pair, lo_value, hi_value)

static inline u32
kvm_read_aaind_tags_reg_value(void)
{
	return KVM_GET_AAU_AAIND_TAG();
}
static inline void
kvm_write_aaind_tags_reg_value(u32 reg_value)
{
	KVM_SET_AAU_AAIND_TAG(reg_value);
}
static inline u64
kvm_read_aaincr_reg_value(int AAINCR_no)
{
	return KVM_GET_AAU_AAINCR(AAINCR_no);
}
static inline void
kvm_write_aaincr_reg_value(int AAINCR_no, u64 reg_value)
{
	KVM_SET_AAU_AAINCR(AAINCR_no, reg_value);
}
static inline u32
kvm_read_aaincr_tags_reg_value(void)
{
	return KVM_GET_AAU_AAINCR_TAG();
}
static inline void
kvm_write_aaincr_tags_reg_value(u32 reg_value)
{
	KVM_SET_AAU_AAINCR_TAG(reg_value);
}

static inline void
kvm_read_aaincrs_pair_value(int AAINCRs_pair, u64 *lo_value, u64 *hi_value)
{
	u64 value1, value2;

	KVM_GET_AAU_AAINCRS(AAINCRs_pair, (AAINCRs_pair + 1), value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
#define	KVM_READ_AAINCRS_PAIR_VALUE_V2(AAINCRs_pair, value1, value2)	\
		KVM_GET_AAU_AAINCRS(AAINCRs_pair, ((AAINCRs_pair) + 1),	\
					value1, value2)
#define	KVM_READ_AAINCRS_PAIR_VALUE_V5(AAINCRs_pair, value1, value2)	\
		KVM_GET_AAU_AAINCRS(AAINCRs_pair, ((AAINCRs_pair) + 1),	\
					value1, value2)
#define	KVM_READ_AAINCR_REG7_AND_TAGS_VALUE_V5(value7, tags)	\
({ \
	value7 = kvm_read_aaincr_reg_value(7);  \
	tags = kvm_read_aaincr_tags_reg_value(); \
})

static inline void
kvm_write_aaincrs_pair_value(int AAINCRs_pair, u64 lo_value, u64 hi_value)
{
	KVM_SET_AAU_AAINCRS(AAINCRs_pair, (AAINCRs_pair + 1),
						lo_value, hi_value);
}
#define	KVM_WRITE_AAINCRS_PAIR_VALUE_V2(AAINCRs_pair, lo_value, hi_value) \
		kvm_write_aaincrs_pair_value(AAINCRs_pair, lo_value, hi_value)
#define	KVM_WRITE_AAINCRS_PAIR_VALUE_V5(AAINCRs_pair, lo_value, hi_value) \
		kvm_write_aaincrs_pair_value(AAINCRs_pair, lo_value, hi_value)

static inline u64
kvm_read_aasti_reg_value(int AASTI_no)
{
	return KVM_GET_AAU_AASTI(AASTI_no);
}
static inline void
kvm_write_aasti_reg_value(int AASTI_no, u64 reg_value)
{
	KVM_SET_AAU_AASTI(AASTI_no, reg_value);
}
static inline u32
kvm_read_aasti_tags_reg_value(void)
{
	return KVM_GET_AAU_AASTI_TAG();
}
static inline void
kvm_write_aasti_tags_reg_value(u32 reg_value)
{
	KVM_SET_AAU_AASTI_TAG(reg_value);
}

static inline void
kvm_read_aastis_pair_value(int AASTIs_pair, u64 *lo_value, u64 *hi_value)
{
	u64 value1, value2;

	KVM_GET_AAU_AASTIS(AASTIs_pair, (AASTIs_pair + 1), value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
#define	KVM_READ_AASTIS_PAIR_VALUE_V2(AASTIs_pair, value1, value2)	\
		KVM_GET_AAU_AASTIS(AASTIs_pair, ((AASTIs_pair) + 1),	\
					value1, value2)
#define	KVM_READ_AASTIS_PAIR_VALUE_V5(AASTIs_pair, value1, value2)	\
		KVM_GET_AAU_AASTIS(AASTIs_pair, ((AASTIs_pair) + 1),	\
					value1, value2)

static inline void
kvm_write_aastis_pair_value(int AASTIs_pair, u64 lo_value, u64 hi_value)
{
	KVM_SET_AAU_AASTIS(AASTIs_pair, (AASTIs_pair + 1), lo_value, hi_value);
}
#define	KVM_WRITE_AASTIS_PAIR_VALUE_V2(AASTIs_pair, lo_value, hi_value)	\
		kvm_write_aastis_pair_value(AASTIs_pair, lo_value, hi_value)
#define	KVM_WRITE_AASTIS_PAIR_VALUE_V5(AASTIs_pair, lo_value, hi_value)	\
		kvm_write_aastis_pair_value(AASTIs_pair, lo_value, hi_value)

static inline void
kvm_read_aaldi_reg_value(int AALDI_no, u64 *l_value, u64 *r_value)
{
	u64 value1, value2;

	KVM_GET_AAU_AALDI(AALDI_no, value1, value2);
	*l_value = value1;
	*r_value = value2;
}
#define	KVM_READ_AALDI_REG_VALUE_V2(AALDI_no, value1, value2)	\
			KVM_GET_AAU_AALDI(AALDI_no, value1, value2)
#define	KVM_READ_AALDI_REG_VALUE_V5(AALDI_no, value1, value2)	\
			KVM_GET_AAU_AALDI(AALDI_no, value1, value2)

static inline void
kvm_write_aaldi_reg_value(int AALDI_no, u64 l_value, u64 r_value)
{
	KVM_SET_AAU_AALDI(AALDI_no, l_value, r_value);
}

static inline void
kvm_read_aaldas_reg_value(int AALDAs_no, u32 *l_value, u32 *r_value)
{
	u32 value1, value2;

	KVM_GET_AAU_AALDA(AALDAs_no, value1, value2);
	*l_value = value1;
	*r_value = value2;
}

static inline void
kvm_write_aaldas_reg_value(int AALDAs_no, u32 l_value, u32 r_value)
{
	KVM_SET_AAU_AALDA(AALDAs_no, l_value, r_value);
}
static inline void
kvm_read_aaldm_reg_value(u32 *lo_value, u32 *hi_value)
{
	u32 value1, value2;

	KVM_GET_AAU_AALDM(value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
static inline void
kvm_write_aaldm_reg_value(u32 lo_value, u32 hi_value)
{
	KVM_SET_AAU_AALDM(lo_value, hi_value);
}
static inline void
kvm_read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	kvm_read_aaldm_reg_value(&aaldm->lo, &aaldm->hi);
}
static inline void
kvm_write_aaldm_reg(e2k_aaldm_t *aaldm)
{
	kvm_write_aaldm_reg_value(aaldm->lo, aaldm->hi);
}
static inline void
kvm_read_aaldv_reg_value(u32 *lo_value, u32 *hi_value)
{
	u32 value1, value2;

	KVM_GET_AAU_AALDV(value1, value2);
	*lo_value = value1;
	*hi_value = value2;
}
static inline void
kvm_write_aaldv_reg_value(u32 lo_value, u32 hi_value)
{
	KVM_SET_AAU_AALDV(lo_value, hi_value);
}
static inline void
kvm_read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	kvm_read_aaldv_reg_value(&aaldv->lo, &aaldv->hi);
}
static inline void
kvm_write_aaldv_reg(e2k_aaldv_t *aaldv)
{
	kvm_write_aaldm_reg_value(aaldv->lo, aaldv->hi);
}

static inline void
kvm_read_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	KVM_GET_AAU_AAD(AAD_no, mem_p);
}

static inline void
kvm_write_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	KVM_SET_AAU_AAD(AAD_no, mem_p);
}

static inline void
kvm_read_aads_4_reg(int AADs_no, e2k_aadj_t *mem_p)
{
	KVM_GET_AAU_4_AADs(AADs_no, mem_p);
}

static inline void
kvm_write_aads_4_reg(int AADs_no, e2k_aadj_t *mem_p)
{
	KVM_SET_AAU_4_AADs(AADs_no, mem_p);
}

#define	kvm_clear_apb()	/* AAU context should restore host */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure kvm kernel without paravirtualization */

#include <asm/kvm/guest/aau_context.h>

static __always_inline u32 read_aasr_reg_value(void)
{
	return kvm_read_aasr_reg_value();
}
static __always_inline void write_aasr_reg_value(u32 reg_value)
{
	kvm_write_aasr_reg_value(reg_value);
}
static __always_inline e2k_aasr_t read_aasr_reg(void)
{
	return kvm_read_aasr_reg();
}
static __always_inline void write_aasr_reg(e2k_aasr_t aasr)
{
	kvm_write_aasr_reg(aasr);
}
static inline u32 read_aafstr_reg_value(void)
{
	return kvm_read_aafstr_reg_value();
}
static inline void write_aafstr_reg_value(u32 reg_value)
{
	kvm_write_aafstr_reg_value(reg_value);
}
static inline void read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	kvm_read_aaldm_reg_value(&aaldm->lo, &aaldm->hi);
}
static inline void write_aaldm_reg(e2k_aaldm_t *aaldm)
{
	kvm_write_aaldm_reg_value(aaldm->lo, aaldm->hi);
}
static inline void read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	kvm_read_aaldv_reg_value(&aaldv->lo, &aaldv->hi);
}
static inline void write_aaldv_reg(e2k_aaldv_t *aaldv)
{
	kvm_write_aaldm_reg_value(aaldv->lo, aaldv->hi);
}

#define clear_apb()	kvm_clear_apb()

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* _KVM_AAU_REGS_ACCESS_H_ */
