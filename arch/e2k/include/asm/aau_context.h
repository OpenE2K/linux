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
#include <linux/uaccess.h>
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
#define LSR_VLC_MASK 0x1
#define LSR_VLC_SHIFT 37

#define get_lcnt(reg)	(reg & LSR_LCNT_MASK)
#define get_ldmc(reg)	((reg >> LSR_LDMC_SHIFT) & LSR_LDMC_MASK)
#define get_ecnt(reg)	((reg >> LSR_ECNT_SHIFT) & LSR_ECNT_MASK)
#define get_pcnt(reg)	((reg >> LSR_PCNT_SHIFT) & LSR_PCNT_MASK)
#define get_vlc(reg)	((reg >> LSR_VLC_SHIFT) & LSR_VLC_MASK)

static inline void
native_get_array_descriptors_v2(e2k_aau_t *context)
{
	NATIVE_GET_ARRAY_DESCRIPTORS_V2(context);
}
static inline void
native_get_array_descriptors_v5(e2k_aau_t *context)
{
	NATIVE_GET_ARRAY_DESCRIPTORS_V5(context);
}

static __always_inline void
native_set_array_descriptors(const e2k_aau_t *context)
{
	NATIVE_SET_ARRAY_DESCRIPTORS(context);
}

static inline void
native_get_synchronous_part_v2(e2k_aau_t *context)
{
	NATIVE_GET_SYNCHRONOUS_PART_V2(context);
}
static inline void
native_get_synchronous_part_v5(e2k_aau_t *context)
{
	NATIVE_GET_SYNCHRONOUS_PART_V5(context);
}

static __always_inline void
native_set_synchronous_part(const e2k_aau_t *context)
{
	NATIVE_SET_SYNCHRONOUS_PART(context);
}

static inline void
native_set_all_aaldis(const u64 aaldis[])
{
	NATIVE_SET_ALL_AALDIS(aaldis);
}

static	inline	void
native_set_all_aaldas(const e2k_aalda_t aaldas_p[])
{
#ifndef __LITTLE_ENDIAN
# error This loads must be little endian to not mix aaldas up (and the same goes to SAVE_AALDA)
#endif
	NATIVE_SET_ALL_AALDAS(aaldas_p);
}

/* set current array prefetch buffer indices values */
static __always_inline void native_set_aau_aaldis_aaldas(
		const struct thread_info *ti, const e2k_aau_t *aau_regs)
{
	native_set_all_aaldis(aau_regs->aaldi);
	native_set_all_aaldas(ti->aalda);
}

/*
 * It's taken that aasr was get earlier(from get_aau_context caller)
 * and comparison with aasr.iab was taken.
 */
static inline void
native_get_aau_context_v2(e2k_aau_t *context)
{
	NATIVE_GET_AAU_CONTEXT_V2(context);
}
static inline void
native_get_aau_context_v5(e2k_aau_t *context)
{
	NATIVE_GET_AAU_CONTEXT_V5(context);
}

/*
 * It's taken that comparison with aasr.iab was taken and assr
 * will be set later.
 */
static __always_inline void
native_set_aau_context(e2k_aau_t *context)
{
	NATIVE_SET_AAU_CONTEXT(context);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure guest kernel without paravirtualization */
#include <asm/kvm/guest/aau_context.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized host and guest kernel */
#include <asm/paravirt/aau_context.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* native kernel without virtualization */
/* or native host kernel with virtualization support */

#define GET_ARRAY_DESCRIPTORS_V2(aau_context)				\
({									\
	native_get_array_descriptors_v2(aau_context);			\
})
#define GET_ARRAY_DESCRIPTORS_V5(aau_context)				\
({									\
	native_get_array_descriptors_v5(aau_context);			\
})
#define	GET_SYNCHRONOUS_PART_V2(aau_context)				\
({									\
	native_get_synchronous_part_v2(aau_context);			\
})
#define	GET_SYNCHRONOUS_PART_V5(aau_context)				\
({									\
	native_get_synchronous_part_v5(aau_context);			\
})

#define	GET_AAU_CONTEXT_V2(cntx)	native_get_aau_context_v2(cntx)
#define	GET_AAU_CONTEXT_V5(cntx)	native_get_aau_context_v5(cntx)

#define	SAVE_AAU_MASK_REGS(aau_context, aasr)			\
		NATIVE_SAVE_AAU_MASK_REGS(aau_context, aasr)

#define	RESTORE_AAU_MASK_REGS(aau_context)				\
		NATIVE_RESTORE_AAU_MASK_REGS(aau_context)

#define SAVE_AADS(aau_regs)						\
		NATIVE_SAVE_AADS(aau_regs)

#define RESTORE_AADS(aau_regs)					\
		NATIVE_RESTORE_AADS(aau_regs)


#define SAVE_AALDIS_V2(regs)	NATIVE_SAVE_AALDIS_V2(regs)
#define SAVE_AALDIS_V5(regs)	NATIVE_SAVE_AALDIS_V5(regs)

#define SAVE_AALDA(aaldas)					\
({								\
	register u32	aalda0, aalda4, aalda8, aalda12,	\
			aalda16, aalda20, aalda24, aalda28,	\
			aalda32, aalda36, aalda40, aalda44,	\
			aalda48, aalda52, aalda56, aalda60;	\
								\
	NATIVE_GET_AAU_AALDA(aalda0, aalda32, aalda0);		\
	NATIVE_GET_AAU_AALDA(aalda4, aalda36, aalda4);		\
	NATIVE_GET_AAU_AALDA(aalda8, aalda40, aalda8);		\
	NATIVE_GET_AAU_AALDA(aalda12, aalda44, aalda12);	\
	NATIVE_GET_AAU_AALDA(aalda16, aalda48, aalda16);	\
	NATIVE_GET_AAU_AALDA(aalda20, aalda52, aalda20);	\
	NATIVE_GET_AAU_AALDA(aalda24, aalda56, aalda24);	\
	NATIVE_GET_AAU_AALDA(aalda28, aalda60, aalda28);	\
	*(u32 *) (&aaldas[0]) = aalda0;				\
	*(u32 *) (&aaldas[4]) = aalda4;				\
	*(u32 *) (&aaldas[8]) = aalda8;				\
	*(u32 *) (&aaldas[12]) = aalda12;			\
	*(u32 *) (&aaldas[16]) = aalda16;			\
	*(u32 *) (&aaldas[20]) = aalda20;			\
	*(u32 *) (&aaldas[24]) = aalda24;			\
	*(u32 *) (&aaldas[28]) = aalda28;			\
	*(u32 *) (&aaldas[32]) = aalda32;			\
	*(u32 *) (&aaldas[36]) = aalda36;			\
	*(u32 *) (&aaldas[40]) = aalda40;			\
	*(u32 *) (&aaldas[44]) = aalda44;			\
	*(u32 *) (&aaldas[48]) = aalda48;			\
	*(u32 *) (&aaldas[52]) = aalda52;			\
	*(u32 *) (&aaldas[56]) = aalda56;			\
	*(u32 *) (&aaldas[60]) = aalda60;			\
})

#define SAVE_AAFSTR(regs)					\
({								\
	regs = native_read_aafstr_reg_value();			\
})
#endif	/* CONFIG_KVM_GUEST_KERNEL */

/* 
 * for code optimization
 */ 
static inline int aau_working(e2k_aau_t *context)
{
	e2k_aasr_t aasr = context->aasr;

	return unlikely(AW(aasr) & (AAU_AASR_IAB | AAU_AASR_STB));
}

#endif /* _E2K_AAU_CONTEXT_H */
