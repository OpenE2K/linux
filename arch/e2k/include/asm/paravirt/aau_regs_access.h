/*
 * AAU registers description, macroses for load/store AAU context
 * paravirtualized case
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

/* do not include this header directly, only through <asm/aau_context.h> */

#ifndef _E2K_ASM_PARAVIRT_AAU_REGS_ACCESS_H_
#define _E2K_ASM_PARAVIRT_AAU_REGS_ACCESS_H_

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline unsigned int pv_read_aasr_reg_value(void)
{
	if (!paravirt_enabled())
		return native_read_aasr_reg_value();
	else
		return pv_cpu_ops.read_aasr_reg_value();
}
static inline void pv_write_aasr_reg_value(unsigned int reg_value)
{
	if (!paravirt_enabled())
		native_write_aasr_reg_value(reg_value);
	else
		pv_cpu_ops.write_aasr_reg_value(reg_value);
}
static inline unsigned int pv_read_aafstr_reg_value(void)
{
	if (!paravirt_enabled())
		return native_read_aafstr_reg_value();
	else
		return pv_cpu_ops.read_aafstr_reg_value();
}
static inline void pv_write_aafstr_reg_value(unsigned int reg_value)
{
	if (!paravirt_enabled())
		native_write_aafstr_reg_value(reg_value);
	else
		pv_cpu_ops.write_aafstr_reg_value(reg_value);
}

static __always_inline e2k_aasr_t
pv_read_aasr_reg(void)
{
	e2k_aasr_t aasr;

	AW(aasr) = pv_read_aasr_reg_value();
	return aasr;
}
static __always_inline void
pv_write_aasr_reg(e2k_aasr_t aasr)
{
	pv_write_aasr_reg_value(AW(aasr));
}

#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/aau_regs_access.h>

static inline u32
pv_read_aaind_reg_value_v3(int AAIND_no)
{
	if (!paravirt_enabled())
		return native_read_aaind_reg_value_v3(AAIND_no);
	else
		return kvm_read_aaind_reg_value(AAIND_no);
}
static inline u64
pv_read_aaind_reg_value_v5(int AAIND_no)
{
	if (!paravirt_enabled())
		return native_read_aaind_reg_value_v5(AAIND_no);
	else
		return kvm_read_aaind_reg_value(AAIND_no);
}
static inline void
pv_write_aaind_reg_value(int AAIND_no, u64 reg_value)
{
	if (!paravirt_enabled())
		native_write_aaind_reg_value(AAIND_no, reg_value);
	else
		kvm_write_aaind_reg_value(AAIND_no, reg_value);
}

static inline void
pv_read_aainds_pair_value_v3(int AAINDs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u32 value1, value2;

		NATIVE_READ_AAINDS_PAIR_VALUE_V3(AAINDs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aainds_pair_value(AAINDs_pair, lo_value, hi_value);
	}
}
static inline void
pv_read_aainds_pair_value_v5(int AAINDs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u64 value1, value2;

		NATIVE_READ_AAINDS_PAIR_VALUE_V5(AAINDs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aainds_pair_value(AAINDs_pair, lo_value, hi_value);
	}
}

static inline void
pv_write_aainds_pair_value(int AAINDs_pair, u64 lo_value, u64 hi_value)
{
	if (!paravirt_enabled())
		native_write_aainds_pair_value(AAINDs_pair, lo_value, hi_value);
	else
		kvm_write_aainds_pair_value(AAINDs_pair, lo_value, hi_value);
}
static inline u32
pv_read_aaind_tags_reg_value(void)
{
	if (!paravirt_enabled())
		return native_read_aaind_tags_reg_value();
	else
		return kvm_read_aaind_tags_reg_value();
}
static inline void
pv_write_aaind_tags_reg_value(u32 reg_value)
{
	if (!paravirt_enabled())
		native_write_aaind_tags_reg_value(reg_value);
	else
		kvm_write_aaind_tags_reg_value(reg_value);
}
static inline u32
pv_read_aaincr_reg_value(int AAINCR_no)
{
	if (!paravirt_enabled())
		return native_read_aaincr_reg_value_v3(AAINCR_no);
	else
		return kvm_read_aaincr_reg_value(AAINCR_no);
}
static inline u64
pv_read_aaincr_reg_value_v5(int AAINCR_no)
{
	if (!paravirt_enabled())
		return native_read_aaincr_reg_value_v5(AAINCR_no);
	else
		return kvm_read_aaincr_reg_value(AAINCR_no);
}
static inline void
pv_write_aaincr_reg_value(int AAINCR_no, u64 reg_value)
{
	if (!paravirt_enabled())
		native_write_aaincr_reg_value(AAINCR_no, reg_value);
	else
		kvm_write_aaincr_reg_value(AAINCR_no, reg_value);
}
static inline u32
pv_read_aaincr_tags_reg_value(void)
{
	if (!paravirt_enabled())
		return native_read_aaincr_tags_reg_value();
	else
		return kvm_read_aaincr_tags_reg_value();
}
static inline void
pv_write_aaincr_tags_reg_value(u32 reg_value)
{
	if (!paravirt_enabled())
		native_write_aaincr_tags_reg_value(reg_value);
	else
		kvm_write_aaincr_tags_reg_value(reg_value);
}

static inline void
pv_read_aaincrs_pair_value_v3(int AAINCRs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u32 value1, value2;

		NATIVE_READ_AAINCRS_PAIR_VALUE_V3(AAINCRs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aaincrs_pair_value(AAINCRs_pair,
						lo_value, hi_value);
	}
}
static inline void
pv_read_aaincrs_pair_value_v5(int AAINCRs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u64 value1, value2;

		NATIVE_READ_AAINCRS_PAIR_VALUE_V5(AAINCRs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aaincrs_pair_value(AAINCRs_pair,
						lo_value, hi_value);
	}
}

static inline void
pv_write_aaincrs_pair_value(int AAINCRs_pair, u64 lo_value, u64 hi_value)
{
	if (!paravirt_enabled())
		native_write_aaincrs_pair_value(AAINCRs_pair,
						lo_value, hi_value);
	else
		kvm_write_aaincrs_pair_value(AAINCRs_pair,
						lo_value, hi_value);
}
static inline u32
pv_read_aasti_reg_value_v3(int AASTI_no)
{
	if (!paravirt_enabled())
		return native_read_aasti_reg_value_v3(AASTI_no);
	else
		return kvm_read_aasti_reg_value(AASTI_no);
}
static inline u64
pv_read_aasti_reg_value_v5(int AASTI_no)
{
	if (!paravirt_enabled())
		return native_read_aasti_reg_value_v5(AASTI_no);
	else
		return kvm_read_aasti_reg_value(AASTI_no);
}
static inline void
pv_write_aasti_reg_value(int AASTI_no, u32 reg_value)
{
	if (!paravirt_enabled())
		native_write_aasti_reg_value(AASTI_no, reg_value);
	else
		kvm_write_aasti_reg_value(AASTI_no, reg_value);
}
static inline u32
pv_read_aasti_tags_reg_value(void)
{
	if (!paravirt_enabled())
		return native_read_aasti_tags_reg_value();
	else
		return kvm_read_aasti_tags_reg_value();
}
static inline void
pv_write_aasti_tags_reg_value(u32 reg_value)
{
	if (!paravirt_enabled())
		native_write_aasti_tags_reg_value(reg_value);
	else
		kvm_write_aasti_tags_reg_value(reg_value);
}

static inline void
pv_read_aastis_pair_value_v3(int AASTIs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u32 value1, value2;

		NATIVE_READ_AASTIS_PAIR_VALUE_V3(AASTIs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aastis_pair_value(AASTIs_pair, lo_value, hi_value);
	}
}
static inline void
pv_read_aastis_pair_value_v5(int AASTIs_pair, u64 *lo_value, u64 *hi_value)
{
	if (!paravirt_enabled()) {
		u64 value1, value2;

		NATIVE_READ_AASTIS_PAIR_VALUE_V5(AASTIs_pair, value1, value2);
		*lo_value = value1;
		*hi_value = value2;
	} else {
		kvm_read_aastis_pair_value(AASTIs_pair, lo_value, hi_value);
	}
}

static inline void
pv_write_aastis_pair_value(int AASTIs_pair, u64 lo_value, u64 hi_value)
{
	if (!paravirt_enabled())
		native_write_aastis_pair_value(AASTIs_pair, lo_value, hi_value);
	else
		kvm_write_aastis_pair_value(AASTIs_pair, lo_value, hi_value);
}

static inline void
pv_read_aaldi_reg_value_v3(int AALDI_no, u64 *l_value, u64 *r_value)
{
	if (!paravirt_enabled())
		native_read_aaldi_reg_value_v3(AALDI_no, l_value, r_value);
	else
		kvm_read_aaldi_reg_value(AALDI_no, l_value, r_value);
}
static inline void
pv_read_aaldi_reg_value_v5(int AALDI_no, u64 *l_value, u64 *r_value)
{
	if (!paravirt_enabled())
		native_read_aaldi_reg_value_v5(AALDI_no, l_value, r_value);
	else
		kvm_read_aaldi_reg_value(AALDI_no, l_value, r_value);
}

static inline void
pv_write_aaldi_reg_value(int AALDI_no, u64 l_value, u64 r_value)
{
	if (!paravirt_enabled())
		native_write_aaldi_reg_value(AALDI_no, l_value, r_value);
	else
		kvm_write_aaldi_reg_value(AALDI_no, l_value, r_value);
}

static inline void
pv_read_aaldas_reg_value(int AALDAs_no, u32 *l_value, u32 *r_value)
{
	if (!paravirt_enabled())
		native_read_aaldas_reg_value(AALDAs_no, l_value, r_value);
	else
		kvm_read_aaldas_reg_value(AALDAs_no, l_value, r_value);
}

static inline void
pv_write_aaldas_reg_value(int AALDAs_no, u32 l_value, u32 r_value)
{
	if (!paravirt_enabled())
		native_write_aaldas_reg_value(AALDAs_no, l_value, r_value);
	else
		kvm_write_aaldas_reg_value(AALDAs_no, l_value, r_value);
}
static inline void
pv_read_aaldm_reg_value(u32 *lo_value, u32 *hi_value)
{
	if (!paravirt_enabled())
		native_read_aaldm_reg_value(lo_value, hi_value);
	else
		kvm_read_aaldm_reg_value(lo_value, hi_value);
}
static inline void
pv_write_aaldm_reg_value(u32 lo_value, u32 hi_value)
{
	if (!paravirt_enabled())
		native_write_aaldm_reg_value(lo_value, hi_value);
	else
		kvm_write_aaldm_reg_value(lo_value, hi_value);
}
static inline void
pv_read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	if (!paravirt_enabled())
		native_read_aaldm_reg(aaldm);
	else
		kvm_read_aaldm_reg(aaldm);
}
static inline void
pv_write_aaldm_reg(e2k_aaldm_t aaldm)
{
	if (!paravirt_enabled())
		native_write_aaldm_reg(aaldm);
	else
		kvm_write_aaldm_reg(aaldm);
}
static inline void
pv_read_aaldv_reg_value(u32 *lo_value, u32 *hi_value)
{
	if (!paravirt_enabled())
		native_read_aaldv_reg_value(lo_value, hi_value);
	else
		kvm_read_aaldv_reg_value(lo_value, hi_value);
}
static inline void
pv_write_aaldv_reg_value(u32 lo_value, u32 hi_value)
{
	if (!paravirt_enabled())
		native_write_aaldv_reg_value(lo_value, hi_value);
	else
		kvm_write_aaldv_reg_value(lo_value, hi_value);
}
static inline void
pv_read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	if (!paravirt_enabled())
		native_read_aaldv_reg(aaldv);
	else
		kvm_read_aaldv_reg(aaldv);
}
static inline void
pv_write_aaldv_reg(e2k_aaldv_t aaldv)
{
	if (!paravirt_enabled())
		native_write_aaldv_reg(aaldv);
	else
		kvm_write_aaldv_reg(aaldv);
}

static inline void
pv_read_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	if (!paravirt_enabled())
		native_read_aad_reg(AAD_no, mem_p);
	else
		kvm_read_aad_reg(AAD_no, mem_p);
}

static inline void
pv_write_aad_reg(int AAD_no, e2k_aadj_t *mem_p)
{
	if (!paravirt_enabled())
		native_write_aad_reg(AAD_no, mem_p);
	else
		kvm_write_aad_reg(AAD_no, mem_p);
}

static inline void
pv_read_aads_4_reg(int AADs_no, e2k_aadj_t *mem_p)
{
	if (!paravirt_enabled())
		native_read_aads_4_reg(AADs_no, mem_p);
	else
		kvm_read_aads_4_reg(AADs_no, mem_p);
}

static inline void
pv_write_aads_4_reg(int AADs_no, e2k_aadj_t *mem_p)
{
	if (!paravirt_enabled())
		native_write_aads_4_reg(AADs_no, mem_p);
	else
		kvm_write_aads_4_reg(AADs_no, mem_p);
}

#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

#include <asm/paravirt/aau_context.h>

static __always_inline u32
read_aasr_reg_value(void)
{
	return pv_read_aasr_reg_value();
}
static __always_inline void
write_aasr_reg_value(u32 reg_value)
{
	pv_write_aasr_reg_value(reg_value);
}
static __always_inline e2k_aasr_t
read_aasr_reg(void)
{
	return pv_read_aasr_reg();
}
static __always_inline void
write_aasr_reg(e2k_aasr_t aasr)
{
	pv_write_aasr_reg(aasr);
}
static inline u32
read_aafstr_reg_value(void)
{
	return pv_read_aafstr_reg_value();
}
static inline void
write_aafstr_reg_value(u32 reg_value)
{
	pv_write_aafstr_reg_value(reg_value);
}
static inline void
read_aaldm_reg(e2k_aaldm_t *aaldm)
{
	pv_read_aaldm_reg_value(&aaldm->lo, &aaldm->hi);
}
static inline void
write_aaldm_reg(e2k_aaldm_t aaldm)
{
	pv_write_aaldm_reg_value(aaldm.lo, aaldm.hi);
}
static inline void
read_aaldv_reg(e2k_aaldv_t *aaldv)
{
	pv_read_aaldv_reg_value(&aaldv->lo, &aaldv->hi);
}
static inline void
write_aaldv_reg(e2k_aaldv_t aaldv)
{
	pv_write_aaldm_reg_value(aaldv.lo, aaldv.hi);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_ASM_PARAVIRT_AAU_REGS_ACCESS_H_ */
