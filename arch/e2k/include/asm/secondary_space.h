/*
 * Secondary space support for E2K binary compiler
 * asm/secondary_space.h
 */
#ifndef _SECONDARY_SPACE_H
#define	_SECONDARY_SPACE_H

#ifndef __ASSEMBLY__
#include <linux/mm_types.h>
#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/smp.h>
#include <asm/mmu_regs.h>
#endif /* !__ASSEMBLY__ */

#define BINCO_PROTOCOL_VERSION	4

#define NATIVE_IS_NEXT_ELBRUS_2S	\
		((int)machine.native_iset_ver >= ELBRUS_2S_ISET)
#define NATIVE_SS_SIZE			\
		((NATIVE_IS_NEXT_ELBRUS_2S) ? \
			(0x800000000000UL) : (0x100000000UL))
#define NATIVE_SS_ADDR_START		\
		(NATIVE_IS_NEXT_ELBRUS_2S ? \
			0x0000400000000000L : 0x0000100000000000L)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/secondary_space.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/secondary_space.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */

#define IS_NEXT_ELBRUS_2S	NATIVE_IS_NEXT_ELBRUS_2S
#define SS_SIZE			NATIVE_SS_SIZE
#define SS_ADDR_START		NATIVE_SS_ADDR_START
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

/*
 * If updating this value - do not forget to update E2K_ARG3_MASK -
 * mask for 63-45 bits and PAGE_OFFSET.
 */
#define SS_ADDR_END		(SS_ADDR_START + SS_SIZE)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define ADDR_IN_SS(a)		((a >= SS_ADDR_START) && (a < SS_ADDR_END))
#else
#define ADDR_IN_SS(a)		0
#endif

#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE, ##__VA_ARGS__)

#ifndef __ASSEMBLY__

extern
s64 sys_el_binary(s64 work, s64 arg2, s64 arg3, s64 arg4);

/*
 * Intreface of el_binary() syscall
 * Work argument(arg1) values:
 */
#define GET_SECONDARY_SPACE_OFFSET	0
#define SET_SECONDARY_REMAP_BOUND	1
#define SET_SECONDARY_DESCRIPTOR	2
#define SET_SECONDARY_MTRR_DEPRECATED	3
#define GET_SECONDARY_MTRR_DEPRECATED	4
#define GET_SNXE_USAGE			5
#define TGKILL_INFO_DEPRECATED		6
#define SIG_EXIT_GROUP			7
#define FLUSH_CMD_CACHES_DEPRECATED	8
#define SET_SC_RSTRT_IGNORE_DEPRECATED	9
#define SET_RP_BOUNDS_AND_IP		10
#define SET_SECONDARY_64BIT_MODE	11
#define GET_PROTOCOL_VERSION		12
#define SET_IC_NEED_FLUSH_ON_SWITCH	13
#define GET_UPT_SEC_AD_SHIFT_DSBL	14
#define SET_UPT_SEC_AD_SHIFT_DSBL	15

/* Selector numbers for GET_SECONDARY_SPACE_OFFSET */
enum sel_num {
	CS_SELECTOR		= 0,
	DS_SELECTOR		= 1,
	ES_SELECTOR		= 2,
	SS_SELECTOR		= 3,
	FS_SELECTOR		= 4,
	GS_SELECTOR		= 5,
};

#define E2K_ARG3_MASK	(0xffffe000ffffffffLL)
#define I32_ADDR_TO_E2K(arg)				\
({							\
	s64 argm;					\
	argm = arg;					\
	if (machine.native_iset_ver < E2K_ISET_V3) {	\
		argm &= E2K_ARG3_MASK;			\
		argm |= SS_ADDR_START;			\
	}						\
	argm;						\
})

#endif /* !__ASSEMBLY__ */
#endif /* _SECONDARY_SPACE_H */
