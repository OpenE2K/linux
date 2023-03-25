#ifndef _UAPI_E2K_BOOTINFO_H_
#define _UAPI_E2K_BOOTINFO_H_

/*
 * The mother board types
 */

#define MB_TYPE_MIN                     0
#define MB_TYPE_E2K_BASE                0x00
#define MB_TYPE_E1CP_BASE		(MB_TYPE_E2K_BASE + 50)
#define	MB_TYPE_ES4_BASE		(MB_TYPE_E2K_BASE + 70)
#define MB_TYPE_E8C_BASE		(MB_TYPE_E2K_BASE + 80)
#define MB_TYPE_MAX			a0

/* By default all mb_versions have cy14b101p rt clock. If no - fix
 * is_cy14b101p_exist() in arch/l/kernel/i2c-spi/core.c
 */

#define MB_TYPE_E1CP_PMC	(MB_TYPE_E1CP_BASE + 0)	/* E1CP with PMC */
#define MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK	/* IOHUB2 razbrakovschik */ \
				(MB_TYPE_E1CP_BASE + 1)
#define MB_TYPE_MBE1C_PC	(MB_TYPE_E1CP_BASE + 2)	/* E1CP with PMC */

#define	MB_TYPE_ES4_MBE2S_PC	(MB_TYPE_ES4_BASE + 0)
#define	MB_TYPE_ES4_PC401	(MB_TYPE_ES4_BASE + 1)

#define MB_TYPE_E8C		(MB_TYPE_E8C_BASE + 0)


/*
 * The cpu types
 */

#define CPU_TYPE_E2S		0x03	/* E2S */
#define CPU_TYPE_E8C		0x07	/* E8C */
#define CPU_TYPE_E1CP		0x08	/* E1C+ */
#define CPU_TYPE_E8C2		0x09	/* E8C */
#define CPU_TYPE_E12C		0xa	/* E12C */
#define CPU_TYPE_E16C		0xb	/* E16C */
#define CPU_TYPE_E2C3		0xc	/* E2C3 */

#define CPU_TYPE_SIMUL		0x3e    /* simulator */

#define	CPU_TYPE_MASK		0x3f	/* mask of CPU type */
#define	PROC_TYPE_MASK		0xc0	/* mask of MicroProcessor type */

#define	GET_CPU_TYPE(type)	(((type) & CPU_TYPE_MASK) >> 0)

/*
 * The cpu types names
 */

#define GET_CPU_TYPE_NAME(type_field)			\
({							\
	unsigned char type = GET_CPU_TYPE(type_field);	\
	char *name;					\
							\
	switch (type) {					\
	case CPU_TYPE_E2S:				\
		name = "E2S";				\
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
	case CPU_TYPE_E12C:				\
		name = "E12C";				\
		break;					\
	case CPU_TYPE_E16C:				\
		name = "E16C";				\
		break;					\
	case CPU_TYPE_E2C3:				\
		name = "E2C3";				\
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

/*
 * The mother board types names
 */

#define GET_MB_TYPE_NAME(type)				\
({							\
	char *name;					\
							\
	switch (type) {					\
	case MB_TYPE_E1CP_PMC:				\
		name = "E1C+ PMC";			\
		break;					\
	case MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK:	\
		name = "IOHUB2 razbrakovschik";		\
		break;					\
	case MB_TYPE_MBE1C_PC:				\
		name = "MBE1C-PC";			\
		break;					\
	case MB_TYPE_ES4_MBE2S_PC:			\
		name = "MBE2S-PC";			\
		break;					\
	case MB_TYPE_ES4_PC401:				\
		name = "PC-401";			\
		break;					\
	case MB_TYPE_E8C:				\
		name = "E8C";				\
		break;					\
	default:					\
		name = "unknown";			\
	}						\
							\
	name;						\
})

#endif /* _UAPI_E2K_BOOTINFO_H_ */
