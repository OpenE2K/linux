#ifndef _SPARC64_BOOTINFO_H_
#define _SPARC64_BOOTINFO_H_

#ifdef __KERNEL__
#include <asm-l/bootinfo.h>

extern	bootblock_struct_t *bootblock;	/* bootblock structure pointer */
					/* passed by boot (bios/prom) */

#define bootblock_virt		bootblock

#if defined(CONFIG_E90S) && defined(NEEDS_GET_DCR)
static inline unsigned long get_dcr(void)
{
	unsigned long dcr;
	__asm__ __volatile__("rd %%dcr, %0"
		: "=r" (dcr)
		: "i" (ASI_DCU_CONTROL_REG));
	 return dcr;
}
#endif
#endif

/* The cpu type names */

#define	CPU_TYPE_MIN	0
#define CPU_TYPE_R150   0x0     /* R150 */
#define CPU_TYPE_R500   0x1     /* R500 */
#define CPU_TYPE_R500S  0x2     /* R500S */
#define CPU_TYPE_4R     0x3     /* 4R */
#define CPU_TYPE_SIMUL  0xfe    /* Simulator */
#define	CPU_TYPE_MAX	0xff

#define GET_CPU_TYPE_NAME(type)                         \
({                                                      \
        char *name;                                     \
                                                        \
        switch (type) {                                 \
                case CPU_TYPE_R150:                     \
                        name = "R150";                  \
                        break;                          \
                case CPU_TYPE_R500:                     \
                        name = "R500";                  \
                        break;                          \
                case CPU_TYPE_R500S:                    \
                        name = "R500S";                 \
                        break;                          \
                case CPU_TYPE_4R:                       \
			name = "R1000";                 \
                        break;                          \
                case CPU_TYPE_SIMUL:                    \
                        name = "SIMUL";                 \
                        break;                          \
                default:                                \
                        name = "unknown";                 \
        }                                               \
                                                        \
        name;                                           \
})

/*  Motherboard type names */
#ifdef CONFIG_E90

#define MB_TYPE_E90_BASE                0x00
#define	MB_TYPE_MIN			0

#define MB_TYPE_E90_NO_PCI              0
#define MB_TYPE_E90_CPCI                1
#define MB_TYPE_E90_MBC		 MB_TYPE_E90_CPCI 
#define MB_TYPE_E90_VK3201	(MB_TYPE_E90_CPCI | (1 << 3))
#define MB_TYPE_E90_MBCC	(MB_TYPE_E90_CPCI | (2 << 3))
#define MB_TYPE_E90_PMC		(MB_TYPE_E90_CPCI | (3 << 3))
#define MB_TYPE_E90_MYPC	(MB_TYPE_E90_CPCI | (4 << 3))
#define MB_TYPE_E90_NOTEBOOK	(MB_TYPE_E90_CPCI | (5 << 3)) 
#define MB_TYPE_E90_MVC                 3
#define MB_TYPE_E90_MB		       (3 | (1 << 3))
#define MB_TYPE_E90_PCPCI               4
#define MB_TYPE_E90_MPJA1               5
#define MB_TYPE_E90_COUSIN              6
#define MB_TYPE_E90_THINCLIENT          7

#define	MB_TYPE_MAX			127


#define mb_type_pci_mask        0x7


#define GET_MB_TYPE_NAME(type)                          \
({                                                      \
        char *name;                                     \
        switch (type) {                                 \
                case MB_TYPE_E90_NO_PCI:                \
                        name = "MB-1";                  \
                        break;                          \
                case MB_TYPE_E90_MBC:                  \
                        name = "MB/C";			\
                        break;                          \
                case MB_TYPE_E90_VK3201:                  \
                        name = "VK32-01";		 \
                        break;                          \
		case MB_TYPE_E90_PMC:			\
                        name = "PMC";			 \
                        break;                          \
                case MB_TYPE_E90_MB:                 	 \
                        name = "MB";			 \
                        break;                          \
                case MB_TYPE_E90_MPJA1:                 \
                        name = "MPY1";                \
                        break;                          \
                case MB_TYPE_E90_MVC:                   \
                        name = "MV/C";                  \
                        break;                          \
                case MB_TYPE_E90_PCPCI:                 \
                        name = "VK32";                  \
                        break;                          \
                case MB_TYPE_E90_NOTEBOOK:              \
                        name = "MPY2";   		  \
                        break;                          \
                case MB_TYPE_E90_MBCC:                  \
                        name = "MBC/C";    		 \
                        break;                          \
                case MB_TYPE_E90_COUSIN:                \
                        name = "OLD-COUSIN";           	\
                        break;                          \
                case MB_TYPE_E90_MYPC:                \
                        name = "MYP/C";           	\
                        break;                          \
                case MB_TYPE_E90_THINCLIENT:            \
                        name = "TY-R500S"; 	   	\
                        break;                          \
                default:                                \
                        name = "unknown";    	       \
        }                                               \
        name;                                           \
})


#define GET_MB_USED_IN(type)				\
({							\
	char *name;					\
	switch(type) {					\
	case MB_TYPE_E90_THINCLIENT:			\
		name = "APM VK-1";			\
		break;					\
	case MB_TYPE_E90_MVC:				\
		name = "VK-27.02, VK-27.03, VK-27.04";	\
		break;					\
	case MB_TYPE_E90_MBC:				\
		name = "VK-27, VK-27.01";		\
		break;					\
	case	MB_TYPE_E90_MBCC:			\
		name = "ELBRUS-90 MICRO - 52";		\
		break;					\
	case MB_TYPE_E90_MYPC:				\
		name = "Management module";		\
		break;					\
	default :					\
		name = NULL;				\
	}						\
	name;						\
})
#endif

#ifdef CONFIG_E90S

#define	MB_TYPE_MIN			128
#define MB_TYPE_E90S			128
#define MB_TYPE_E90S_BUTTERFLY		128
#define MB_TYPE_E90S_CPCI		129
#define MB_TYPE_E90S_PC			130
#define MB_TYPE_E90S_ATX		131
#define MB_TYPE_E90S_NT			132
#define MB_TYPE_E90S_SIVUCH2		133
#define	MB_TYPE_E90S_MBC4_1_C		134
#define	MB_TYPE_E90S_MPU3_C		135
#define	MB_TYPE_E90S_MPU6_C		136
#define	MB_TYPE_E90S_MPU_COM		137
#define	MB_TYPE_E90S_MPU_MPC		138
#define	MB_TYPE_E90S_IZUMRUD		139
#define	MB_TYPE_E90S_REJECTOR		140
/* By default all mb_versions > MB_TYPE_E90S_REJECTOR
 * have cy14b101p rt clock. If no correct is_cy14b101p_exist()
 * in arch/l/kernel/i2c-spi/core.c
 */

#define	MB_TYPE_MAX			150

#define GET_MB_TYPE_NAME(type)				\
({							\
        char *name;					\
        switch (type) {					\
                case MB_TYPE_E90S_BUTTERFLY:		\
                        name = "MB90C/C";		\
                        break;				\
                case MB_TYPE_E90S_CPCI:			\
                        name = "MBC4/C";		\
                        break;				\
                case MB_TYPE_E90S_PC:			\
                        name = "MBC4-PC";		\
                        break;				\
                case MB_TYPE_E90S_MPU6_C:		\
                        name = "MPU6/C";		\
                        break;				\
                case MB_TYPE_E90S_MPU3_C:		\
                        name = "MPU3/C";		\
                        break;				\
                case MB_TYPE_E90S_ATX:			\
                        name = "MPU-ATX";		\
                        break;				\
                case MB_TYPE_E90S_MPU_MPC:		\
                        name = "MPU-MPC";		\
                        break;				\
                case MB_TYPE_E90S_NT:			\
			name = "NT-MCST4R";		\
                        break;				\
                case MB_TYPE_E90S_SIVUCH2:		\
                        name = "MP1C2/V";		\
                        break;				\
                case MB_TYPE_E90S_MBC4_1_C:		\
                        name = "MMBC4_1/C";		\
                        break;                          \
                case MB_TYPE_E90S_IZUMRUD:		\
                        name = "IZUMRUD";		\
                        break;                          \
                case MB_TYPE_E90S_REJECTOR:		\
                        name = "REJECTOR";		\
                        break;                          \
                default:				\
                        name = "unknown";		\
        }						\
        name;						\
})



#define GET_MB_USED_IN(type)				\
({							\
	char *name;					\
	switch (type) {					\
	case MB_TYPE_E90S_BUTTERFLY:			\
		name = "ELBRUS-90C";			\
		break;					\
	case MB_TYPE_E90S_MBC4_1_C:			\
		name = "VK 27.05";			\
		break;					\
	default:					\
		name = NULL;				\
	}						\
	name;						\
})


#endif
#endif /* _SPARC64_BOOTINFO_H_ */

