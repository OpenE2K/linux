#ifndef _E2K_BOOTINFO_H_
#define _E2K_BOOTINFO_H_

#ifdef __KERNEL__
#include <asm-l/bootinfo.h>
#endif

/*
 * The mother board types
 */

#define MB_TYPE_MIN                     0
#define MB_TYPE_E2K_BASE                0x00
#define MB_TYPE_E3M_BASE                (MB_TYPE_E2K_BASE + 1)
#define MB_TYPE_ES2_BASE                (MB_TYPE_E2K_BASE + 20)
#define MB_TYPE_E1CP_BASE		(MB_TYPE_E2K_BASE + 50)
#define	MB_TYPE_ES4_BASE		(70)
#define MB_TYPE_MAX			80

#define MB_TYPE_E3M1                    (MB_TYPE_E3M_BASE + 0)  /* First testing complexes */
                                                                /* in ATX body: south bridge */
                                                                /* device number is 7, */
                                                                /* interconnection of */
                                                                /* interrupts is ABCD */
#define MB_TYPE_E3M_FLAT1               (MB_TYPE_E3M_BASE + 1)  /* Comlexes in flat black */
#define MB_TYPE_E3M_FLAT2               (MB_TYPE_E3M_BASE + 2)  /* bodies: south bridge */
                                                                /* device number is 20, */
                                                                /* interconnection of */
                                                                /* interrupts is BCDA (for */
                                                                /* value 2) or DABC ( for */
                                                                /* value 3) */
#define MB_TYPE_E3M_COMPACT_PCI_DUMMY   (MB_TYPE_E3M_BASE + 3)  /* Complexes in Compact PCI */
                                                                /* bodies (dummy) */
#define MB_TYPE_E3M_COMPACT_PCI         (MB_TYPE_E3M_BASE + 4)  /* Complexes in Compact PCI */
                                                                /* bodies */
#define	MB_TYPE_E3M_KVS			(MB_TYPE_E3M_BASE + 5)	/* E3M + IOHUB */
#define MB_TYPE_ES2_M133MG_C		(MB_TYPE_E3M_KVS)
#define MB_TYPE_ES2_M133M_C		(MB_TYPE_E3M_BASE + 6)

#define MB_TYPE_ES2_PLATO1		(MB_TYPE_ES2_BASE + 0)
#define MB_TYPE_ES2_BUTTERFLY		(MB_TYPE_ES2_BASE + 1)
#define MB_TYPE_ES2_RTC_FM33256		(MB_TYPE_ES2_BASE + 2)	/* FM332aa56 rtc */
#define MB_TYPE_ES2_RTC_CY14B101P	(MB_TYPE_ES2_BASE + 3)	/* CY14B101P rtc */
#define MB_TYPE_ES2_APORIA		(MB_TYPE_ES2_BASE + 5)  /* APORIA */
#define MB_TYPE_ES2_NT			(MB_TYPE_ES2_BASE + 6)  /* Nosimyi terminal */
/* Use this when CLKRs are not synchronized across the system */
#define MB_TYPE_ES2_RTC_CY14B101P_MULTICLOCK (MB_TYPE_ES2_BASE + 7)
#define MB_TYPE_ES2_CUB_COM		(MB_TYPE_ES2_BASE + 8)
#define MB_TYPE_ES2_MBCUB_C		(MB_TYPE_ES2_BASE + 11)
#define MB_TYPE_ES2_MB3S1_C		(MB_TYPE_ES2_BUTTERFLY)
#define	MB_TYPE_ES2_MB3S_C_K		(MB_TYPE_ES2_BASE + 14)
#define	MB_TYPE_ES2_MGA3D		(MB_TYPE_ES2_BASE + 15)
#define	MB_TYPE_ES2_BC_M4211		(MB_TYPE_ES2_BASE + 16)
#define	MB_TYPE_ES2_EL2S4		(MB_TYPE_ES2_BASE + 17)
/* By default all mb_versions > MB_TYPE_ES2_EL2S4 && < MB_TYPE_E1CP_BASE
 * have cy14b101p rt clock. If no correct is_cy14b101p_exist()
 * in arch/l/kernel/i2c-spi/core.c
 */

#define MB_TYPE_E1CP_PMC		(MB_TYPE_E1CP_BASE + 0)	/* E1CP with PMC */
#define MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK	(MB_TYPE_E1CP_BASE + 1)	/* IOHUB2 razbrakovschik */

#define	MB_TYPE_ES4_MBE2S_PC		(MB_TYPE_ES4_BASE + 0)


/*
 * The cpu types
 */

#define CPU_TYPE_MIN		0
#define CPU_TYPE_E3M		0x01	/* E3M */
#define CPU_TYPE_E3S		0x02	/* E3S */
#define CPU_TYPE_E2S		0x03	/* E2S */
#define CPU_TYPE_ES2_DSP	0x04	/* E2C+ */
#define CPU_TYPE_ES2_RU		0x06	/* E2C Micron */
#define CPU_TYPE_E8C		0x07	/* E8C */
#define CPU_TYPE_E1CP		0x08	/* E1C+ */
#define CPU_TYPE_E8C2		0x09	/* E8C */
#define	CPU_TYPE_IS_VIRT	0x40	/* CPU type is virtual */

#define	CPU_TYPE_MASK		0x3f	/* mask of CPU type */
#define	CPU_TYPE_MAX		(CPU_TYPE_MASK + 1)

#define	CPU_TYPE_VIRT_E3M	(CPU_TYPE_E3M | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_E3S	(CPU_TYPE_E3S | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_E2S	(CPU_TYPE_E2S | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_ES2_DSP	(CPU_TYPE_ES2_DSP | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_ES2_RU	(CPU_TYPE_ES2_RU | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_E8C	(CPU_TYPE_E8C | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_E1CP	(CPU_TYPE_E1CP | CPU_TYPE_IS_VIRT)
#define	CPU_TYPE_VIRT_E8C2	(CPU_TYPE_E8C2 | CPU_TYPE_IS_VIRT)
#define CPU_TYPE_SIMUL		0x3e    /* simulator */

#define	GET_CPU_TYPE(type)	((type) & CPU_TYPE_MASK)
#define	IS_CPU_TYPE_VIRT(type)	((type) & CPU_TYPE_IS_VIRT)

/*
 * The cpu types names
 */

#define GET_CPU_TYPE_NAME(type_field)			\
({							\
	unsigned char type = GET_CPU_TYPE(type_field);	\
	char *name;					\
							\
	switch (type) {					\
	case CPU_TYPE_E3M:				\
		name = "E3M";				\
		break;					\
	case CPU_TYPE_E3S:				\
	case CPU_TYPE_VIRT_E3S:				\
		name = "E3S";				\
		break;					\
	case CPU_TYPE_E2S:				\
		name = "E2S";				\
		break;					\
	case CPU_TYPE_ES2_DSP:				\
		name = "E2C+DSP";			\
		break;					\
	case CPU_TYPE_ES2_RU:				\
		name = "E1C";				\
		break;					\
	case CPU_TYPE_E8C:				\
		name = "E8C";				\
		break;					\
	case CPU_TYPE_E1CP:				\
		name = "E1C+";				\
		break;					\
	case CPU_TYPE_E8C2:				\
		name = "E8C2";				\
		break;					\
	case CPU_TYPE_SIMUL:				\
		name = "SIMUL";				\
		break;					\
	default:					\
		name = "unknown";			\
	}						\
							\
	name;						\
})

#define	GET_VIRT_MACHINE_ID(type_field)			\
({							\
	unsigned char type = GET_CPU_TYPE(type_field);	\
	int virt_mach_id = 0;				\
							\
	switch (type) {					\
	case CPU_TYPE_E3M:				\
		virt_mach_id = MACHINE_ID_E3M;		\
		break;					\
	case CPU_TYPE_E3S:				\
		virt_mach_id = MACHINE_ID_E3S;		\
		break;					\
	case CPU_TYPE_E2S:				\
		virt_mach_id = MACHINE_ID_E2S;		\
		break;					\
	case CPU_TYPE_ES2_DSP:				\
		virt_mach_id = MACHINE_ID_ES2_DSP;	\
		break;					\
	case CPU_TYPE_ES2_RU:				\
		virt_mach_id = MACHINE_ID_ES2_RU;	\
		break;					\
	case CPU_TYPE_E8C:				\
		virt_mach_id = MACHINE_ID_E8C;		\
		break;					\
	case CPU_TYPE_E1CP:				\
		virt_mach_id = MACHINE_ID_E1CP;		\
		break;					\
	case CPU_TYPE_E8C2:				\
		virt_mach_id = MACHINE_ID_E8C2;		\
		break;					\
	case CPU_TYPE_SIMUL:				\
		virt_mach_id = MACHINE_ID_SIMUL;	\
		break;					\
	default:					\
		virt_mach_id = MACHINE_ID_NONE;		\
	}						\
	if (IS_CPU_TYPE_VIRT(type_field))		\
		virt_mach_id |= MACHINE_ID_VIRT;	\
							\
	virt_mach_id;					\
})

/*
 * The mother board types names
 */

#define GET_MB_TYPE_NAME(type)				\
({							\
	char *name;					\
							\
	switch (type) {					\
	case MB_TYPE_E3M1:				\
		name = "E3M1";				\
		break;					\
	case MB_TYPE_ES2_M133MG_C:			\
		name = "M133MG/C";			\
		break;					\
	case MB_TYPE_ES2_M133M_C:			\
		name = "M133M/C";			\
		break;					\
	case MB_TYPE_ES2_MB3S1_C:			\
		name = "MB3S1/C";			\
		break;					\
	case MB_TYPE_ES2_MBCUB_C:			\
	case MB_TYPE_ES2_PLATO1:			\
		name = "MBKUB/C";			\
		break;					\
	case MB_TYPE_ES2_MB3S_C_K:			\
		name = "MB3S/C-K";			\
		break;					\
	case MB_TYPE_ES2_NT:				\
		name = "NT-ELBRUS-S";			\
		break;					\
	case MB_TYPE_ES2_CUB_COM:			\
		name = "CUB-COM";			\
		break;					\
	case MB_TYPE_ES2_RTC_FM33256:			\
		name = "MONOCUB+FM33256";		\
		break;					\
	case MB_TYPE_ES2_RTC_CY14B101P:			\
		name = "MONOCUB";			\
		break;					\
	case MB_TYPE_ES2_RTC_CY14B101P_MULTICLOCK:	\
		name = "MP1C1/V";			\
		break;					\
	case MB_TYPE_ES2_EL2S4:				\
		name = "EL2S4";				\
		break;					\
	case MB_TYPE_ES2_MGA3D:				\
		name = "MGA3D";				\
		break;					\
	case MB_TYPE_ES2_BC_M4211:			\
		name = "BC-M4211";			\
		break;					\
	case MB_TYPE_E1CP_PMC:				\
		name = "E1C+ PMC";			\
		break;					\
	case MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK:	\
		name = "IOHUB2 razbrakovschik";		\
		break;					\
	case MB_TYPE_ES4_MBE2S_PC:			\
		name = "MBE2S-PC";			\
		break;					\
	default:					\
		name = "unknown";			\
	}						\
							\
	name;						\
})

#define GET_MB_USED_IN(type)					\
({								\
	char *name;						\
								\
	switch (type) {						\
	case MB_TYPE_ES2_PLATO1:				\
		name = "Plato wtith softreset error";		\
		break;						\
	case MB_TYPE_ES2_MBCUB_C:				\
		name = "APM VK-2, APM VK-120, BV632, BV631";	\
		break;						\
	case MB_TYPE_ES2_M133MG_C:				\
		name = "KVS-1, UVK/C-A";			\
		break;						\
	case MB_TYPE_ES2_M133M_C:				\
		name = "UVK/C-012, ELBRUS-3A, UVK/C-110";	\
		break;						\
	case MB_TYPE_ES2_MB3S1_C:				\
		name = "ELBRUS-3C-CVS, ELBRUS-3C";		\
		break;						\
	case MB_TYPE_ES2_RTC_FM33256:				\
		name = "MONOCUB+FM33256";			\
		break;						\
	case MB_TYPE_ES2_RTC_CY14B101P:				\
		name = "MONOCUB-M, MONOCUB-PC";			\
		break;						\
	default:						\
		name = NULL;					\
	}							\
								\
	name;							\
})


#endif /* _E2K_BOOTINFO_H_ */
