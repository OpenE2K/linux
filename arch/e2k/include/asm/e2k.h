#ifndef _ASM_E2K_H_
#define _ASM_E2K_H_

#include <linux/types.h>
#include <linux/init.h>
#include <asm/e2k_api.h>
#include <asm/sections.h>

#include <asm/e3m.h>
#include <asm/lms.h>
#include <asm/e3m_iohub.h>
#include <asm/e3m_iohub_lms.h>
#include <asm/e3s.h>
#include <asm/e3s_lms.h>
#include <asm/e2s.h>
#include <asm/e2s_lms.h>
#include <asm/es2.h>
#include <asm/es2_lms.h>
#include <asm/e8c.h>
#include <asm/e8c_lms.h>
#include <asm/e1cp.h>
#include <asm/e1cp_lms.h>
#include <asm/e8c2.h>
#include <asm/e8c2_lms.h>

/* CPU model numbers */
#define	IDR_E3M_MDL		0x01
#define	IDR_E3S_MDL		0x02
#define	IDR_E2S_MDL		0x03
#define	IDR_ES2_DSP_MDL		0x04	/* e2c+ DSP */
#define	IDR_E4S_MDL		0x05
#define	IDR_ES2_RU_MDL		0x06	/* e2c (without DSP) russian MICRON */
#define IDR_E8C_MDL		0x07
#define IDR_E1CP_MDL		0x08	/* one processor e2s + graphic */
#define IDR_E8C2_MDL		0x09

#define	MACHINE_ID_NONE			0x0000
#define	MACHINE_ID_CPU_TYPE_MASK	0x000f
#define	MACHINE_ID_SIMUL		0x0010
#define	MACHINE_ID_E2K_FULL_SIC		0x0020
#define MACHINE_ID_E2K_IOHUB		0x0040
#define MACHINE_ID_E2K_IOMMU		0x0080
#define	MACHINE_ID_E2K_LEGACY_SIC	0x0100	/* host bridge & legacy NBSR */
#define	MACHINE_ID_VIRT			0x8000

#define	MACHINE_ID_E3M			(IDR_E3M_MDL)
#define MACHINE_ID_E3M_IOHUB		(IDR_E3M_MDL | \
						MACHINE_ID_E2K_IOHUB)
#define	MACHINE_ID_E3S			(IDR_E3S_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB)
#define	MACHINE_ID_ES2_DSP		(IDR_ES2_DSP_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB)
#define	MACHINE_ID_ES2_RU		(IDR_ES2_RU_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB)
#define	MACHINE_ID_E2S			(IDR_E2S_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E8C			(IDR_E8C_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E1CP			(IDR_E1CP_MDL | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_E2K_IOHUB | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E8C2			(IDR_E8C2_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOHUB | \
						MACHINE_ID_E2K_IOMMU)

#define	MACHINE_ID_E3M_LMS		(MACHINE_ID_E3M | MACHINE_ID_SIMUL)
#define MACHINE_ID_E3M_IOHUB_LMS	(MACHINE_ID_E3M_IOHUB | \
						MACHINE_ID_SIMUL)
#define	MACHINE_ID_E3S_LMS		(MACHINE_ID_E3S | MACHINE_ID_SIMUL)
#define	MACHINE_ID_ES2_DSP_LMS		(MACHINE_ID_ES2_DSP |	\
						MACHINE_ID_SIMUL)
#define	MACHINE_ID_ES2_RU_LMS		(MACHINE_ID_ES2_RU | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E2S_LMS		(MACHINE_ID_E2S | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E8C_LMS		(MACHINE_ID_E8C | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E1CP_LMS		(MACHINE_ID_E1CP | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E8C2_LMS		(MACHINE_ID_E8C2 | MACHINE_ID_SIMUL)

#define	MACHINE_ID_VIRT_E3M		(MACHINE_ID_E3M | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E3S		(MACHINE_ID_E3S | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_ES2_DSP		(MACHINE_ID_ES2_DSP | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_ES2_RU		(MACHINE_ID_ES2_RU | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E2S		(MACHINE_ID_E2S | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E8C		(MACHINE_ID_E8C | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E1CP		(MACHINE_ID_E1CP | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E8C2		(MACHINE_ID_E8C2 | MACHINE_ID_VIRT)

#ifdef	CONFIG_E2K_MACHINE
 #if	defined(CONFIG_E2K_E3M_SIM)
  #define	machine_id		MACHINE_ID_E3M_LMS
  #define	virt_machine_id		MACHINE_ID_E3M
 #elif	defined(CONFIG_E2K_E3M_IOHUB_SIM)
  #define	machine_id		MACHINE_ID_E3M_IOHUB_LMS
  #define	virt_machine_id		MACHINE_ID_E3M
 #elif	defined(CONFIG_E2K_E3S_SIM)
  #define	machine_id		MACHINE_ID_E3S_LMS
  #define	virt_machine_id		MACHINE_ID_E3S
 #elif	defined(CONFIG_E2K_ES2_DSP_SIM)
  #define	machine_id		MACHINE_ID_ES2_DSP_LMS
  #define	virt_machine_id		MACHINE_ID_ES2_DSP
 #elif	defined(CONFIG_E2K_ES2_RU_SIM)
  #define	machine_id		MACHINE_ID_ES2_RU_LMS
  #define	virt_machine_id		MACHINE_ID_ES2_RU
 #elif	defined(CONFIG_E2K_E2S_SIM)
  #define	machine_id		MACHINE_ID_E2S_LMS
  #define	virt_machine_id		MACHINE_ID_E2S
 #elif	defined(CONFIG_E2K_E8C_SIM)
  #define	machine_id		MACHINE_ID_E8C_LMS
  #define	virt_machine_id		MACHINE_ID_E8C
 #elif	defined(CONFIG_E2K_E1CP_SIM)
  #define	machine_id		MACHINE_ID_E1CP_LMS
  #define	virt_machine_id		MACHINE_ID_E1CP
 #elif	defined(CONFIG_E2K_E8C2_SIM)
  #define	machine_id		MACHINE_ID_E8C2_LMS
  #define	virt_machine_id		MACHINE_ID_E8C2
 #elif	defined(CONFIG_E2K_E3M)
  #define	machine_id		MACHINE_ID_E3M
  #define	virt_machine_id		MACHINE_ID_E3M
 #elif	defined(CONFIG_E2K_E3M_IOHUB)
  #define	machine_id		MACHINE_ID_E3M_IOHUB
  #define	virt_machine_id		MACHINE_ID_E3M
 #elif	defined(CONFIG_E2K_E3S)
  #define	machine_id		MACHINE_ID_E3S
  #define	virt_machine_id		MACHINE_ID_E3S
 #elif	defined(CONFIG_E2K_ES2_DSP)
  #define	machine_id		MACHINE_ID_ES2_DSP
  #define	virt_machine_id		MACHINE_ID_ES2_DSP
 #elif	defined(CONFIG_E2K_ES2_RU)
  #define	machine_id		MACHINE_ID_ES2_RU
  #define	virt_machine_id		MACHINE_ID_ES2_RU
 #elif	defined(CONFIG_E2K_E2S)
  #define	machine_id		MACHINE_ID_E2S
  #define	virt_machine_id		MACHINE_ID_E2S
 #elif	defined(CONFIG_E2K_E8C)
  #define	machine_id		MACHINE_ID_E8C
  #define	virt_machine_id		MACHINE_ID_E8C
 #elif	defined(CONFIG_E2K_E1CP)
  #define	machine_id		MACHINE_ID_E1CP
  #define	virt_machine_id		MACHINE_ID_E1CP
 #elif	defined(CONFIG_E2K_E8C2)
  #define	machine_id		MACHINE_ID_E8C2
  #define	virt_machine_id		MACHINE_ID_E8C2
 #else
  #	error "E2K MACHINE type does not defined"
 #endif
#elif	defined(CONFIG_E3M)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_E3M_LMS
 #define	virt_machine_id		MACHINE_ID_E3M
#elif	defined(CONFIG_E3S)	/* can be defined only for our boot on lms */
  #define	machine_id		MACHINE_ID_E3S_LMS
  #define	virt_machine_id		MACHINE_ID_E3S
#elif	defined(CONFIG_ES2)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_ES2_DSP_LMS
 #if	!defined(CONFIG_VIRT_E3S)
  #define	virt_machine_id		MACHINE_ID_ES2_DSP
 #else	/* defined CONFIG_VIRT_E3S */
  #define	virt_machine_id		MACHINE_ID_VIRT_E3S
 #endif	/* ! CONFIG_VIRT_E3S */
#elif	defined(CONFIG_E2S)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_E2S_LMS
 #define	virt_machine_id		MACHINE_ID_E2S
#elif	defined(CONFIG_E8C)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_E8C_LMS
 #define	virt_machine_id		MACHINE_ID_E8C
#elif	defined(CONFIG_E1CP)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_E1CP_LMS
 #define	virt_machine_id		MACHINE_ID_E1CP
#elif	defined(CONFIG_E8C2)	/* can be defined only for our boot on lms */
 #define	machine_id		MACHINE_ID_E8C2_LMS
 #define	virt_machine_id		MACHINE_ID_E8C2
#else	/* ! CONFIG_E2K_MACHINE && ! our boot on lms */
extern	int __nodedata machine_id;
extern	int virt_machine_id;
#endif /* CONFIG_E2K_MACHINE */

#define	IS_MACHINE_E3M_HW	((machine_id == MACHINE_ID_E3M) || \
					(machine_id == MACHINE_ID_E3M_IOHUB))
#define	IS_MACHINE_E3S_HW	(machine_id == MACHINE_ID_E3S)
#define	IS_MACHINE_ES2_DSP_HW	(machine_id == MACHINE_ID_ES2_DSP)
#define	IS_MACHINE_ES2_RU_HW	(machine_id == MACHINE_ID_ES2_RU)
#define	IS_MACHINE_ES2_HW	(IS_MACHINE_ES2_DSP_HW || IS_MACHINE_ES2_RU_HW)
#define	IS_MACHINE_E2S_HW	(machine_id == MACHINE_ID_E2S)
#define	IS_MACHINE_E8C_HW	(machine_id == MACHINE_ID_E8C)
#define	IS_MACHINE_E1CP_HW	(machine_id == MACHINE_ID_E1CP)
#define	IS_MACHINE_E8C2_HW	(machine_id == MACHINE_ID_E8C2)

#define	IS_MACHINE_E3M_SIM	((machine_id == MACHINE_ID_E3M_LMS) || \
					(machine_id == \
						MACHINE_ID_E3M_IOHUB_LMS))
#define	IS_MACHINE_E3S_SIM	(machine_id == MACHINE_ID_E3S_LMS)
#define	IS_MACHINE_E3M_IOHUB	((IS_MACHINE_E3M) && (HAS_MACHINE_E2K_IOHUB))
#define	IS_MACHINE_ES2_DSP_SIM	(machine_id == MACHINE_ID_ES2_DSP_LMS)
#define	IS_MACHINE_ES2_RU_SIM	(machine_id == MACHINE_ID_ES2_RU_LMS)
#define	IS_MACHINE_ES2_SIM	(IS_MACHINE_ES2_DSP_SIM ||	\
					IS_MACHINE_ES2_RU_SIM)
#define	IS_MACHINE_E2S_SIM	(machine_id == MACHINE_ID_E2S_LMS)
#define	IS_MACHINE_E8C_SIM	(machine_id == MACHINE_ID_E8C_LMS)
#define	IS_MACHINE_E1CP_SIM	(machine_id == MACHINE_ID_E1CP_LMS)
#define	IS_MACHINE_E8C2_SIM	(machine_id == MACHINE_ID_E8C2_LMS)

#define	IS_MACHINE_E3M		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E3M_MDL)
#define	IS_MACHINE_E3S		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E3S_MDL)
#define	IS_MACHINE_ES2_DSP	((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_ES2_DSP_MDL)
#define	IS_MACHINE_ES2_RU	((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_ES2_RU_MDL)
#define	IS_MACHINE_ES2		((IS_MACHINE_ES2_DSP) || (IS_MACHINE_ES2_RU))
#define	IS_MACHINE_E2S		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E2S_MDL)
#define	IS_MACHINE_E8C		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E8C_MDL)
#define	IS_MACHINE_E1CP		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E1CP_MDL)
#define	IS_MACHINE_E8C2		((machine_id & MACHINE_ID_CPU_TYPE_MASK) \
						== IDR_E8C2_MDL)

#define	IS_MACHINE_VIRT_E3M	(virt_machine_id == MACHINE_ID_VIRT_E3M)
#define	IS_MACHINE_VIRT_E3S	(virt_machine_id == MACHINE_ID_VIRT_E3S)
#define	IS_MACHINE_VIRT_ES2_DSP	(virt_machine_id ==	\
					MACHINE_ID_VIRT_ES2_DSP)
#define	IS_MACHINE_VIRT_ES2_RU	(virt_machine_id == MACHINE_ID_VIRT_ES2_RU)
#define	IS_MACHINE_VIRT_ES2	(IS_MACHINE_VIRT_ES2_DSP ||	\
					IS_MACHINE_VIRT_ES2_RU)
#define	IS_MACHINE_VIRT_E2S	(virt_machine_id == MACHINE_ID_VIRT_E2S)
#define	IS_MACHINE_VIRT_E8C	(virt_machine_id == MACHINE_ID_VIRT_E8C)
#define	IS_MACHINE_VIRT_E1CP	(virt_machine_id == MACHINE_ID_VIRT_E1CP)
#define	IS_MACHINE_VIRT_E8C2	(virt_machine_id == MACHINE_ID_VIRT_E8C2)

#define	IS_MACHINE_HW		((machine_id & MACHINE_ID_SIMUL) == 0)
#define	IS_MACHINE_SIM		((machine_id & MACHINE_ID_SIMUL) != 0)

#define	HAS_MACHINE_E2K_DSP	(IS_MACHINE_ES2_DSP)
#define	HAS_MACHINE_E2K_FULL_SIC	\
		((machine_id & MACHINE_ID_E2K_FULL_SIC) != 0)
#define HAS_MACHINE_E2K_IOHUB	((machine_id & MACHINE_ID_E2K_IOHUB) != 0)
#define HAS_MACHINE_E2K_IOMMU	((machine_id & MACHINE_ID_E2K_IOMMU) != 0)
#define	HAS_MACHINE_E2K_LEGACY_SIC	\
		((machine_id & MACHINE_ID_E2K_LEGACY_SIC) != 0)
#define	HAS_MACHINE_L_SIC		\
		(HAS_MACHINE_E2K_FULL_SIC || HAS_MACHINE_E2K_LEGACY_SIC)

#define	HAS_MACHINE_VIRT_CPU	((virt_machine_id & MACHINE_ID_VIRT) != 0)

#define	BOOT_IS_MACHINE_E3M_HW	((boot_machine_id == MACHINE_ID_E3M) || \
					(boot_machine_id == \
						MACHINE_ID_E3M_IOHUB))
#define	BOOT_IS_MACHINE_E3S_HW	(boot_machine_id == MACHINE_ID_E3S)
#define	BOOT_IS_MACHINE_ES2_DSP_HW	\
				(boot_machine_id == MACHINE_ID_ES2_DSP)
#define	BOOT_IS_MACHINE_ES2_RU_HW	\
				(boot_machine_id == MACHINE_ID_ES2_RU)
#define	BOOT_IS_MACHINE_ES2_HW	(BOOT_IS_MACHINE_ES2_DSP_HW ||	\
					BOOT_IS_MACHINE_ES2_RU_HW)
#define	BOOT_IS_MACHINE_E2S_HW	(boot_machine_id == MACHINE_ID_E2S)
#define	BOOT_IS_MACHINE_E8C_HW	(boot_machine_id == MACHINE_ID_E8C)
#define	BOOT_IS_MACHINE_E1CP_HW	(boot_machine_id == MACHINE_ID_E1CP)
#define	BOOT_IS_MACHINE_E8C2_HW	(boot_machine_id == MACHINE_ID_E8C2)

#define	BOOT_IS_MACHINE_E3M_SIM	((boot_machine_id == MACHINE_ID_E3M_LMS) || \
					(boot_machine_id == \
						MACHINE_ID_E3M_IOHUB_LMS))
#define	BOOT_IS_MACHINE_E3S_SIM	(boot_machine_id == MACHINE_ID_E3S_LMS)
#define	BOOT_IS_MACHINE_ES2_DSP_SIM	\
				(boot_machine_id == MACHINE_ID_ES2_DSP_LMS)
#define	BOOT_IS_MACHINE_ES2_RU_SIM	\
				(boot_machine_id == MACHINE_ID_ES2_RU_LMS)
#define	BOOT_IS_MACHINE_ES2_SIM	(BOOT_IS_MACHINE_ES2_DSP_SIM ||	\
					BOOT_IS_MACHINE_ES2_RU_SIM)
#define	BOOT_IS_MACHINE_E2S_SIM	(boot_machine_id == MACHINE_ID_E2S_LMS)
#define	BOOT_IS_MACHINE_E8C_SIM	(boot_machine_id == MACHINE_ID_E8C_LMS)
#define	BOOT_IS_MACHINE_E1CP_SIM	\
		(boot_machine_id == MACHINE_ID_E1CP_LMS)
#define	BOOT_IS_MACHINE_E8C2_SIM	\
		(boot_machine_id == MACHINE_ID_E8C2_LMS)

#define	BOOT_IS_MACHINE_E3M	((BOOT_IS_MACHINE_E3M_HW) || \
					(BOOT_IS_MACHINE_E3M_SIM))
#define	BOOT_IS_MACHINE_E3S	((BOOT_IS_MACHINE_E3S_HW) || \
					(BOOT_IS_MACHINE_E3S_SIM))
#define	BOOT_IS_MACHINE_ES2_DSP	((BOOT_IS_MACHINE_ES2_DSP_HW) || \
					(BOOT_IS_MACHINE_ES2_DSP_SIM))
#define	BOOT_IS_MACHINE_ES2_RU	((BOOT_IS_MACHINE_ES2_RU_HW) || \
					(BOOT_IS_MACHINE_ES2_RU_SIM))
#define	BOOT_IS_MACHINE_ES2	((BOOT_IS_MACHINE_ES2_HW) || \
					(BOOT_IS_MACHINE_ES2_SIM))
#define	BOOT_IS_MACHINE_E2S	((BOOT_IS_MACHINE_E2S_HW) || \
					(BOOT_IS_MACHINE_E2S_SIM))
#define	BOOT_IS_MACHINE_E8C	((BOOT_IS_MACHINE_E8C_HW) || \
					(BOOT_IS_MACHINE_E8C_SIM))
#define	BOOT_IS_MACHINE_E1CP	((BOOT_IS_MACHINE_E1CP_HW) || \
					(BOOT_IS_MACHINE_E1CP_SIM))
#define	BOOT_IS_MACHINE_E8C2	((BOOT_IS_MACHINE_E8C2_HW) || \
					(BOOT_IS_MACHINE_E8C2_SIM))

#define	BOOT_IS_MACHINE_HW	((boot_machine_id & MACHINE_ID_SIMUL) == 0)
#define	BOOT_IS_MACHINE_SIM	((boot_machine_id & MACHINE_ID_SIMUL) != 0)

#define	BOOT_HAS_MACHINE_E2K_FULL_SIC	\
		((boot_machine_id & MACHINE_ID_E2K_FULL_SIC) != 0)
#define BOOT_HAS_MACHINE_E2K_IOHUB	\
		((boot_machine_id & MACHINE_ID_E2K_IOHUB) != 0)
#define	BOOT_HAS_MACHINE_E2K_LEGACY_SIC	\
		((boot_machine_id & MACHINE_ID_E2K_LEGACY_SIC) != 0)
#define	BOOT_HAS_MACHINE_L_SIC		\
		(BOOT_HAS_MACHINE_E2K_FULL_SIC || \
			BOOT_HAS_MACHINE_E2K_LEGACY_SIC)

extern int is_virt_cpu_enabled(int cpuid);
#define	IS_VIRT_CPU_ENABLED(cpuid)	is_virt_cpu_enabled(cpuid)

/* E2K physical address difinitions */
#define	MAX_PA_SIZE	40			/* E2K physical address size */
						/* (bits number) */
#define	MAX_PA_MSB	(MAX_PA_SIZE - 1)	/* The number of the most */
						/* significant bit of E2K */
						/* physical address */
#define	MAX_PA_MASK	((1UL << MAX_PA_SIZE) - 1)
#define	MAX_PM_SIZE	(1UL << MAX_PA_SIZE)

/* E2K virtual address difinitions */
#define	MAX_VA_SIZE	59			/* Virtual address maximum */
						/* size (bits number) */
#define	MAX_VA_MSB	(MAX_VA_SIZE -1)	/* The maximum number of the */
						/* most significant bit of */
						/* virtual address */
#define	MAX_VA_MASK	((1UL << MAX_VA_SIZE) - 1)

#define	E2K_VA_SIZE	48			/* E2K Virtual address size */
						/* (bits number) */
#define	E2K_VA_MSB	(E2K_VA_SIZE - 1)	/* The number of the most */
						/* significant bit of E2K */
						/* virtual address */
#define	E2K_VA_MASK	((1UL << E2K_VA_SIZE) - 1)


#define	MAX_NODE_CPUS		16 /* all 16 CPU cores on a node */

/*
 * IO links and IO controllers specifications
 * E3M machines use Intel's chipset PIIX4 connected through own north bridge
 * All other machines use IO links and own chipset and main IO buses controller
 * is IOHUB.
 * Without losing generality, IO controller of E3M can consider as connected
 * through simple IO link too, but it needs do not forget that IO controller
 * is PIIX4 while details are essential
 */

#ifndef	CONFIG_E2K_MACHINE
#define	E2K_MAX_NODE_IOLINKS	2	/* each node can has max 2 IO links */
					/* connected to IOHUB or RDMA */
#define	MACH_MAX_NUMIOLINKS	(E2K_MAX_NODE_IOLINKS * MAX_NUMNODES)
#else  /* CONFIG_E2K_MACHINE */
#define	E2K_MAX_NODE_IOLINKS	2
#define	MACH_MAX_NUMIOLINKS						\
	((IS_MACHINE_E3M) ? (E3M_MAX_NUMIOLINKS) :			\
		((IS_MACHINE_E3M_IOHUB) ? (E3M_IOHUB_MAX_NUMIOLINKS) :	\
		((IS_MACHINE_E3S)	? (E3S_MAX_NUMIOLINKS)  :	\
		((IS_MACHINE_ES2)	? (ES2_MAX_NUMIOLINKS)  :	\
		((IS_MACHINE_E2S)	? (E2S_MAX_NUMIOLINKS)  :	\
		((IS_MACHINE_E8C)	? (E8C_MAX_NUMIOLINKS)  :	\
		((IS_MACHINE_E1CP)	? (E1CP_MAX_NUMIOLINKS) :	\
			E8C2_MAX_NUMIOLINKS)))))))
#endif /* ! CONFIG_E2K_MACHINE */

#ifdef	CONFIG_E2K_MACHINE
#if defined(CONFIG_E2K_E3M_SIM) || defined(CONFIG_E2K_E3M_IOHUB_SIM) ||	  \
	defined(CONFIG_E2K_E3S_SIM) || defined(CONFIG_E2K_ES2_DSP_SIM) || \
	defined(CONFIG_E2K_ES2_RU_SIM) || defined(CONFIG_E2K_E2S_SIM) ||  \
	defined(CONFIG_E2K_E8C_SIM) || defined(CONFIG_E2K_E1CP_SIM) ||	  \
	defined(CONFIG_E2K_E8C2_SIM)
#define E2K_HALT_OK()			E2K_LMS_HALT_OK
#define E2K_HALT_ERROR(err_no)		\
({					\
	dump_stack();			\
	E2K_LMS_HALT_ERROR(err_no);	\
})
#define BOOT_E2K_HALT_OK()		E2K_LMS_HALT_OK
#define BOOT_E2K_HALT_ERROR(err_no)	E2K_LMS_HALT_ERROR(err_no)
#elif defined(CONFIG_E2K_E3M) || defined(CONFIG_E2K_E3M_IOHUB) ||	\
	defined(CONFIG_E2K_E3S) || defined(CONFIG_E2K_ES2_DSP) ||	\
	defined(CONFIG_E2K_ES2_RU) || defined(CONFIG_E2K_E2S) ||	\
	defined(CONFIG_E2K_E8C) || defined(CONFIG_E2K_E1CP) ||		\
	defined(CONFIG_E2K_E8C2)
#define E2K_HALT_OK()			{while(1);}
#define E2K_HALT_ERROR(err_no)		panic("HALT_ERROR(%d)\n", err_no)
#define BOOT_E2K_HALT_OK()		{while(1);}
#define BOOT_E2K_HALT_ERROR(err_no)	do_boot_printk("HALT_ERROR(%d)\n", \
								err_no)
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
#define	E2K_HALT_OK()						\
({								\
	if (IS_MACHINE_SIM) {					\
		E2K_LMS_HALT_OK;				\
	}							\
	while (1) {						\
	}							\
})
#define	E2K_HALT_ERROR(err_no)					\
({								\
	if (IS_MACHINE_SIM) {					\
		dump_stack();					\
		E2K_LMS_HALT_ERROR(err_no);			\
	}							\
	panic("HALT_ERROR(%d)\n", err_no);			\
})
#define	BOOT_E2K_HALT_OK()					\
({								\
	if (BOOT_IS_MACHINE_SIM) {				\
		E2K_LMS_HALT_OK;				\
	}							\
	while (1) {						\
	}							\
})
#define	BOOT_E2K_HALT_ERROR(err_no)				\
({								\
	if (BOOT_IS_MACHINE_SIM) {				\
		E2K_LMS_HALT_ERROR(err_no);			\
	}							\
	do_boot_printk("HALT_ERROR(%d)\n", err_no);		\
})
#endif /* CONFIG_E2K_MACHINE */

#define	LMS_CONS_DATA_PORT	0x300UL	/* On READ  - data from keyboard      */
					/* On WRITE - data to debug ouput     */
					/* port (console/journal)             */

#define	LMS_CONS_STATUS_PORT	0x301UL	/* On READ  - data available on 0x300 */
					/* On WRITE - shift count   for 0x304 */

#define	LMS_NSOCK_BADDR_PORT	0x302UL	/* On READ  - network socket base addr*/
					/* On WRITE - the same.		      */

#define	LMS_NSOCK_DATA_PORT	0x303UL	/* On READ  - data from network socket*/
					/* On WRITE - data   to network socket*/

#define	LMS_TRACE_CNTL_PORT	0x304UL	/* On READ  - state of the instruction*/
					/* counter */
					/* On WRITE - LMS tracer control      */
					/* (1 - start, 0 - stop)              */

#define	LMS_TRACE_CNTL_OFF	0
#define	LMS_TRACE_CNTL_ON	1

#define	BOOT_E2K_CPU_STARTUP_ADDR					\
		((BOOT_HAS_MACHINE_E2K_FULL_SIC) ?			\
			(E2K_SIC_CPU_STARTUP_ADDR)			\
			:						\
			((BOOT_HAS_MACHINE_E2K_LEGACY_SIC) ?		\
				(E2K_LEGACY_SIC_CPU_STARTUP_ADDR)	\
				:					\
				(E3M_CPU_STARTUP_ADDR)))

#ifndef	CONFIG_E2K_MACHINE
extern void __init e2k_setup_machine(void);
#endif	/* CONFIG_E2K_MACHINE */
extern void __init e2k_setup_arch(void);

extern void write_back_cache_ipi(void *);
extern int e3m_get_vector(void);

extern unsigned long machine_serial_num;

#endif /* _ASM_E2K_H_ */
