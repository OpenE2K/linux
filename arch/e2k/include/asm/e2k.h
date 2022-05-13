#ifndef _ASM_E2K_H_
#define _ASM_E2K_H_

#include <linux/types.h>
#include <linux/init.h>

#include <asm/cpu_regs_types.h> /* E2K_VA_MSB */
#include <asm/e2k_api.h>
#include <asm/sections.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e1cp.h>
#include <asm/e8c2.h>

/* CPU model numbers */
#define	IDR_E2K_VIRT_MDL	0x00	/* machine is virtual, so CPUs also */

#define	MACHINE_ID_NONE			0x0000
#define	MACHINE_ID_CPU_TYPE_MASK	0x000f
#define	MACHINE_ID_SIMUL		0x0010
#define	MACHINE_ID_E2K_FULL_SIC		0x0020
#define MACHINE_ID_L_IOMMU		0x0040
#define	MACHINE_ID_E2K_LEGACY_SIC	0x0080	/* host bridge & legacy NBSR */
#define	MACHINE_ID_E2K_VIRT_IO		0x0100	/* machine is virtual and */
						/* IO simulates on user level */
						/* (for example by QEMU) */
#define	MACHINE_ID_HW_VIRT		0x0200	/* hardware virtualized VM */
#define	MACHINE_ID_VIRT			0x0400	/* soft paravirtualized VM */
#define MACHINE_ID_E2K_IOMMU		0x0800

#define	MACHINE_ID_E2S			(IDR_E2S_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_L_IOMMU)
#define	MACHINE_ID_E8C			(IDR_E8C_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_L_IOMMU)
#define	MACHINE_ID_E1CP			(IDR_E1CP_MDL | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_L_IOMMU)
#define	MACHINE_ID_E8C2			(IDR_E8C2_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_L_IOMMU)
/*
 * IO_* NBSRs are absent in models with EIOHub. Using LEGACY_SIC with FULL_SIC
 * helps to avoid reading those NBSRs while still using IO_AREA_PHYS_BASE
 * defined for FULL_SIC
 */
#define	MACHINE_ID_E12C			(IDR_E12C_MDL | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E16C			(IDR_E16C_MDL | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E2C3			(IDR_E2C3_MDL | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOMMU)
#define	MACHINE_ID_E2K_VIRT		(IDR_E2K_VIRT_MDL | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_VIRT_IO)
#define	MACHINE_ID_E2K_HW_VIRT		(IDR_E2K_VIRT_MDL | \
						MACHINE_ID_HW_VIRT | \
						MACHINE_ID_E2K_LEGACY_SIC | \
						MACHINE_ID_E2K_FULL_SIC | \
						MACHINE_ID_E2K_IOMMU | \
						MACHINE_ID_E2K_VIRT_IO)

#define	MACHINE_ID_E2S_LMS		(MACHINE_ID_E2S | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E8C_LMS		(MACHINE_ID_E8C | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E1CP_LMS		(MACHINE_ID_E1CP | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E8C2_LMS		(MACHINE_ID_E8C2 | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E12C_LMS		(MACHINE_ID_E12C | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E16C_LMS		(MACHINE_ID_E16C | MACHINE_ID_SIMUL)
#define	MACHINE_ID_E2C3_LMS		(MACHINE_ID_E2C3 | MACHINE_ID_SIMUL)

#define	MACHINE_ID_VIRT_E2S		(MACHINE_ID_E2S | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E8C		(MACHINE_ID_E8C | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E1CP		(MACHINE_ID_E1CP | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E8C2		(MACHINE_ID_E8C2 | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E12C		(MACHINE_ID_E12C | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E16C		(MACHINE_ID_E16C | MACHINE_ID_VIRT)
#define	MACHINE_ID_VIRT_E2C3		(MACHINE_ID_E2C3 | MACHINE_ID_VIRT)

#ifdef CONFIG_E2K_SIMULATOR
# define MACHINE_SIMUL_FLAG MACHINE_ID_SIMUL
#else
# define MACHINE_SIMUL_FLAG 0
#endif

#ifdef	CONFIG_E2K_MACHINE
 #if	defined(CONFIG_E2K_E2S)
  #define native_machine_id	(MACHINE_ID_E2S | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E8C)
  #define native_machine_id	(MACHINE_ID_E8C | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E1CP)
  #define native_machine_id	(MACHINE_ID_E1CP | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E8C2)
  #define native_machine_id	(MACHINE_ID_E8C2 | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E12C)
  #define native_machine_id	(MACHINE_ID_E12C | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E16C)
  #define native_machine_id	(MACHINE_ID_E16C | MACHINE_SIMUL_FLAG)
 #elif	defined(CONFIG_E2K_E2C3)
  #define native_machine_id	(MACHINE_ID_E2C3 | MACHINE_SIMUL_FLAG)
 #else
  #	error "E2K MACHINE type does not defined"
 #endif
#elif	defined(CONFIG_E2S)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E2S_LMS
#elif	defined(CONFIG_E8C)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E8C_LMS
#elif	defined(CONFIG_E1CP)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E1CP_LMS
#elif	defined(CONFIG_E8C2)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E8C2_LMS
#elif	defined(CONFIG_E12C)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E12C_LMS
#elif	defined(CONFIG_E16C)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E16C_LMS
#elif	defined(CONFIG_E2C3)	/* can be defined only for tiny boot on lms */
 #define	native_machine_id	MACHINE_ID_E2C3_LMS
#else	/* ! CONFIG_E2K_MACHINE && ! our boot on lms */
extern unsigned int __nodedata native_machine_id;
#endif /* CONFIG_E2K_MACHINE */

extern const char *e2k_get_cpu_type_name(int mach_type_id);
extern const char *e2k_get_mach_type_name(int mach_type_id);
extern int e2k_get_machine_type_name(int mach_id);
extern void __init native_setup_machine(void);
extern void native_set_mach_type_id(void);
extern const char *native_get_mach_type_name(void);

extern void e2k_init_IRQ(void);

#define	IS_THE_MACHINE_E2S(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E2S_MDL)
#define	IS_THE_MACHINE_E8C(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E8C_MDL)
#define	IS_THE_MACHINE_E1CP(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E1CP_MDL)
#define	IS_THE_MACHINE_E8C2(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E8C2_MDL)
#define	IS_THE_MACHINE_E12C(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E12C_MDL)
#define	IS_THE_MACHINE_E16C(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E16C_MDL)
#define	IS_THE_MACHINE_E2C3(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E2C3_MDL)
#define	IS_THE_MACHINE_E2K_VIRT(mach_id)	\
		(((mach_id) & MACHINE_ID_CPU_TYPE_MASK) == IDR_E2K_VIRT_MDL)

#define	IS_THE_MACHINE_SIM(mach_id)	\
		(((mach_id) & MACHINE_ID_SIMUL) != 0)

#define	HAS_THE_MACHINE_E2K_FULL_SIC(mach_id)	\
		(((mach_id) & MACHINE_ID_E2K_FULL_SIC) != 0)
#define HAS_THE_MACHINE_L_IOMMU(mach_id)	\
		(((mach_id) & MACHINE_ID_L_IOMMU) != 0)
#define HAS_THE_MACHINE_E2K_IOMMU(mach_id)	\
		(((mach_id) & MACHINE_ID_E2K_IOMMU) != 0)
#define	HAS_THE_MACHINE_E2K_LEGACY_SIC(mach_id)	\
		(((mach_id) & MACHINE_ID_E2K_LEGACY_SIC) != 0)
#define	HAS_THE_MACHINE_L_SIC(mach_id)		\
		(HAS_THE_MACHINE_E2K_FULL_SIC(mach_id) || \
			HAS_THE_MACHINE_E2K_LEGACY_SIC(mach_id))

#define	NATIVE_IS_MACHINE_E2S		\
		IS_THE_MACHINE_E2S(native_machine_id)
#define	NATIVE_IS_MACHINE_E8C		\
		IS_THE_MACHINE_E8C(native_machine_id)
#define	NATIVE_IS_MACHINE_E1CP		\
		IS_THE_MACHINE_E1CP(native_machine_id)
#define	NATIVE_IS_MACHINE_E8C2		\
		IS_THE_MACHINE_E8C2(native_machine_id)
#define	NATIVE_IS_MACHINE_E12C		\
		IS_THE_MACHINE_E12C(native_machine_id)
#define	NATIVE_IS_MACHINE_E16C		\
		IS_THE_MACHINE_E16C(native_machine_id)
#define	NATIVE_IS_MACHINE_E2C3		\
		IS_THE_MACHINE_E2C3(native_machine_id)
#define	NATIVE_IS_MACHINE_E2K_VIRT	(false)

#define	BOOT_NATIVE_IS_MACHINE_E2S	\
		IS_THE_MACHINE_E2S(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E8C	\
		IS_THE_MACHINE_E8C(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E1CP	\
		IS_THE_MACHINE_E1CP(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E8C2	\
		IS_THE_MACHINE_E8C2(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E12C	\
		IS_THE_MACHINE_E12C(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E16C	\
		IS_THE_MACHINE_E16C(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E2C3	\
		IS_THE_MACHINE_E2C2(boot_native_machine_id)
#define	BOOT_NATIVE_IS_MACHINE_E2K_VIRT	false

#define	NATIVE_IS_MACHINE_SIM		\
		IS_THE_MACHINE_SIM(native_machine_id)

#define	NATIVE_HAS_MACHINE_E2K_FULL_SIC	\
		HAS_THE_MACHINE_E2K_FULL_SIC(native_machine_id)
#define NATIVE_HAS_MACHINE_E2K_IOMMU	\
		HAS_THE_MACHINE_E2K_IOMMU(native_machine_id)
#define	NATIVE_HAS_MACHINE_E2K_LEGACY_SIC	\
		HAS_THE_MACHINE_E2K_LEGACY_SIC(native_machine_id)
#define	NATIVE_HAS_MACHINE_L_SIC	\
		HAS_THE_MACHINE_L_SIC(native_machine_id)

#define	BOOT_NATIVE_IS_MACHINE_SIM	\
		IS_THE_MACHINE_SIM(boot_native_machine_id)

#define	BOOT_NATIVE_HAS_MACHINE_E2K_FULL_SIC	\
		HAS_THE_MACHINE_E2K_FULL_SIC(boot_native_machine_id)
#define	BOOT_NATIVE_HAS_MACHINE_E2K_LEGACY_SIC	\
		HAS_THE_MACHINE_E2K_LEGACY_SIC(boot_native_machine_id)
#define	BOOT_NATIVE_HAS_MACHINE_L_SIC		\
		HAS_THE_MACHINE_L_SIC(boot_native_machine_id)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel */
#include <asm/kvm/guest/e2k.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/e2k.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */
/* only native machine is exists and should be examined */
#define	machine_id			native_machine_id
#define	boot_machine_id			boot_native_machine_id

#define	get_machine_id()		machine_id
#define	boot_get_machine_id()		boot_machine_id
#define	set_machine_id(mach_id)		(machine_id = (mach_id))
#define	boot_set_machine_id(mach_id)	(boot_machine_id = (mach_id))

static inline void set_mach_type_id(void)
{
	native_set_mach_type_id();
}

#define	boot_panic(fmt, args...)	boot_native_panic(fmt, ##args)

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#define	IS_MACHINE_E2S		\
		IS_THE_MACHINE_E2S(get_machine_id())
#define	IS_MACHINE_E8C		\
		IS_THE_MACHINE_E8C(get_machine_id())
#define	IS_MACHINE_E1CP		\
		IS_THE_MACHINE_E1CP(get_machine_id())
#define	IS_MACHINE_E8C2		\
		IS_THE_MACHINE_E8C2(get_machine_id())
#define	IS_MACHINE_E12C		\
		IS_THE_MACHINE_E12C(get_machine_id())
#define	IS_MACHINE_E16C		\
		IS_THE_MACHINE_E16C(get_machine_id())
#define	IS_MACHINE_E2C3		\
		IS_THE_MACHINE_E2C3(get_machine_id())
#define IS_MACHINE_E2K_VIRT	\
		IS_THE_MACHINE_E2K_VIRT(get_machine_id())

#define	HAS_MACHINE_E2K_FULL_SIC	\
		HAS_THE_MACHINE_E2K_FULL_SIC(get_machine_id())
#define HAS_MACHINE_L_IOMMU	\
		HAS_THE_MACHINE_L_IOMMU(get_machine_id())
#define HAS_MACHINE_E2K_IOMMU	\
		HAS_THE_MACHINE_E2K_IOMMU(get_machine_id())
#define	HAS_MACHINE_E2K_LEGACY_SIC	\
		HAS_THE_MACHINE_E2K_LEGACY_SIC(get_machine_id())
#define	HAS_MACHINE_L_SIC	\
		HAS_THE_MACHINE_L_SIC(get_machine_id())

#define	BOOT_IS_MACHINE_E2S	\
		IS_THE_MACHINE_E2S(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E8C	\
		IS_THE_MACHINE_E8C(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E1CP	\
		IS_THE_MACHINE_E1CP(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E8C2	\
		IS_THE_MACHINE_E8C2(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E12C	\
		IS_THE_MACHINE_E12C(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E16C	\
		IS_THE_MACHINE_E16C(boot_get_machine_id())
#define	BOOT_IS_MACHINE_E2C3	\
		IS_THE_MACHINE_E2C3(boot_get_machine_id())
#define BOOT_IS_MACHINE_VIRT	\
		IS_THE_MACHINE_VIRT(boot_get_machine_id())

#define	BOOT_HAS_MACHINE_E2K_FULL_SIC	\
		HAS_THE_MACHINE_E2K_FULL_SIC(boot_get_machine_id())
#define BOOT_HAS_MACHINE_L_IOMMU	\
		HAS_THE_MACHINE_L_IOMMU(boot_get_machine_id())
#define BOOT_HAS_MACHINE_E2K_IOMMU	\
		HAS_THE_MACHINE_E2K_IOMMU(boot_get_machine_id())
#define	BOOT_HAS_MACHINE_E2K_LEGACY_SIC	\
		HAS_THE_MACHINE_E2K_LEGACY_SIC(boot_get_machine_id())
#define	BOOT_HAS_MACHINE_L_SIC		\
		HAS_THE_MACHINE_L_SIC(boot_get_machine_id())

#define	MAX_NODE_CPUS		16	/* all 16 CPU cores on a node */

#define	E2K_MAX_NODE_IOLINKS	2	/* each node can has max 2 IO links */
					/* connected to IOHUB or RDMA */
#define	MACH_MAX_NUMIOLINKS	(E2K_MAX_NODE_IOLINKS * MAX_NUMNODES)

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

#define	LMS_RAM_ADDR_PORT	0x309UL	/* On WRITE - RAM address to load */
					/* kernel image by simulator */

#define	LMS_TRACE_CNTL_OFF	0
#define	LMS_TRACE_CNTL_ON	1

#define	LMS_LOAD_IMAGE_TO_RAM	5	/* Load 'romimage' file to RAM from */
					/* address before written to */
					/* 'LMS_RAM_ADDR_PORT' port */

extern unsigned long machine_serial_num;

#define ELBRUS_CPU_VENDOR	"Elbrus-MCST"

#endif /* _ASM_E2K_H_ */
