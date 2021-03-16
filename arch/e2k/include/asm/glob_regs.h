/*
 *
 * Copyright (C) 2014 MCST
 *
 * CPU global registers using by kernel
 */
#ifndef _E2K_GLOB_REGS_H
#define _E2K_GLOB_REGS_H

#ifdef __KERNEL__

#include <linux/types.h>

/*
 * MAP of global registers using for the user purposes
 */
#define	E2K_GLOBAL_REGS_NUM	E2K_MAXGR_d
#define	GLOBAL_GREGS_START	0
#define	GLOBAL_GREGS_NUM	(E2K_GLOBAL_REGS_NUM / 2)
#define	LOCAL_GREGS_START	(GLOBAL_GREGS_START + GLOBAL_GREGS_NUM)
#define	LOCAL_GREGS_NUM		(E2K_GLOBAL_REGS_NUM - GLOBAL_GREGS_NUM)

/* Follow global registers are global for user applications according to ABI */
#define	GLOBAL_GREGS_USER_MASK		\
( \
	1UL << 0 | 1UL << 1 |		/* %dg0 - %dg1 */ \
	1UL << 2 | 1UL << 3 |		/* %dg2 - %dg3 */ \
	1UL << 4 | 1UL << 5 |		/* %dg4 - %dg5 */ \
	1UL << 6 | 1UL << 7 |		/* %dg6 - %dg7 */ \
	1UL << 8 | 1UL << 9 |		/* %dg8 - %dg9 */ \
	1UL << 10 | 1UL << 11 |		/* %dg10 - %dg11 */ \
	1UL << 12 | 1UL << 13 |		/* %dg12 - %dg13 */ \
	1UL << 14 | 1UL << 15 |		/* %dg14 - %dg15 */ \
	0UL \
)
/* Follow global registers are local for user applications according to ABI */
#define	LOCAL_GREGS_USER_MASK		\
( \
	1UL << 16 | 1UL << 17 |		/* %dg16 - %dg17 */ \
	1UL << 18 | 1UL << 19 |		/* %dg18 - %dg19 */ \
	1UL << 20 | 1UL << 21 |		/* %dg20 - %dg21 */ \
	1UL << 22 | 1UL << 23 |		/* %dg22 - %dg23 */ \
	1UL << 24 | 1UL << 25 |		/* %dg24 - %dg25 */ \
	1UL << 26 | 1UL << 27 |		/* %dg26 - %dg27 */ \
	1UL << 28 | 1UL << 29 |		/* %dg28 - %dg29 */ \
	1UL << 30 | 1UL << 31 |		/* %dg30 - %dg31 */ \
	0UL \
)

#define	USER_THREAD_TLS_GREG	13	/* TLS of user threads */

/*
 * MAP of global registers using for the kernel purposes
 */

/* THe next register is used only at paravirtualization mode on host & guest */
#define GUEST_VCPU_STATE_GREG	16	/* pointer to VCPU state structure */
/* Global registers to point to current structure	*/
#define	CURRENT_TASK_GREG	17	/* pointer to current task structure */
/*	smp_processor_id() & per_cpu_offset		*/
#define	MY_CPU_OFFSET_GREG	18	/* offset of per CPU data */
#define	SMP_CPU_ID_GREG		19	/* CPU number */
#define	KERNEL_GREGS_MAX_NUM	 4	/* kernel use 4 global registers */

#ifdef	CONFIG_VIRTUALIZATION
/* Global register to support virtualization */
#define	HOST_GREGS_MAX_NUM	 1	/* 1 global register is used by host */
					/* kernel to support virtualization */
#endif	/* CONFIG_VIRTUALIZATION */

#define	CURRENTS_GREGS_MASK	((1UL << GUEST_VCPU_STATE_GREG) |	\
					(1UL << CURRENT_TASK_GREG))
#define	CPUS_GREGS_MASK		((1UL << MY_CPU_OFFSET_GREG) |		\
					(1UL << SMP_CPU_ID_GREG))
#define	KERNEL_GREGS_MAX_MASK	(CURRENTS_GREGS_MASK | CPUS_GREGS_MASK)
#ifdef CONFIG_GREGS_CONTEXT
#define	NATIVE_KERNEL_GREGS_MAX_NUM	KERNEL_GREGS_MAX_NUM
#define	CURRENTS_GREGS_KERNEL_MASK	CURRENTS_GREGS_MASK
#define	CPUS_GREGS_KERNEL_MASK		CPUS_GREGS_MASK
#else	/* ! CONFIG_GREGS_CONTEXT */
#define	NATIVE_KERNEL_GREGS_MAX_NUM	0
#define	CURRENTS_GREGS_KERNEL_MASK	0UL
#define	CPUS_GREGS_KERNEL_MASK		0UL
#endif	/* CONFIG_GREGS_CONTEXT */

#define	NATIVE_KERNEL_GREGS_MASK	\
		(CURRENTS_GREGS_KERNEL_MASK | CPUS_GREGS_KERNEL_MASK)

#ifdef	CONFIG_VIRTUALIZATION
/* Global register to point to guest VCPU state */
#define	VCPU_STATE_GREGS_MASK		(1UL << GUEST_VCPU_STATE_GREG)
#define	VCPU_STATE_GREGS_PAIR_MASK	\
		(VCPU_STATE_GREGS_MASK | (1UL << CURRENT_TASK_GREG))

#define	HOST_KERNEL_GREGS_MAX_NUM	HOST_GREGS_MAX_NUM
#define	HOST_GREGS_KERNEL_MASK		VCPU_STATE_GREGS_MASK
#define	HOST_GREGS_PAIR_KERNEL_MASK	VCPU_STATE_GREGS_PAIR_MASK
#else	/* ! CONFIG_VIRTUALIZATION */
#define	HOST_KERNEL_GREGS_MAX_NUM	0
#define	HOST_GREGS_KERNEL_MASK		0UL
#define	HOST_GREGS_PAIR_KERNEL_MASK	0UL
#endif	/* CONFIG_VIRTUALIZATION */

#define	HOST_KERNEL_GREGS_MASK		HOST_GREGS_KERNEL_MASK
#define	HOST_KERNEL_GREGS_PAIR_MASK	HOST_GREGS_PAIR_KERNEL_MASK

/* Guest kernel can use global registers too (now only same as native kernel) */
/* and addition registers on host to support virtulaization (now only one */
/* register as pointer to VCPU state structure). */
/* All guest global registers are saved/restored by host */
/* Host can not now is guest used own global registers, so should */
/* save/restore on max */
#define	GUEST_GREGS_NUM		KERNEL_GREGS_MAX_NUM
#define	GUEST_GREGS_MASK	KERNEL_GREGS_MAX_MASK

/* real number & mask of registers used by kernel */
/* in accordance with config variables anf execution mode */
#define	KERNEL_GREGS_NUM	NATIVE_KERNEL_GREGS_MAX_NUM
#define	KERNEL_GREGS_MASK	NATIVE_KERNEL_GREGS_MASK

/*
 * Global register used by user and kernel, so it need save/restore
 * some global registers state while enter to/return from kernel.
 * Global registers can contain tagged values and be used by protected
 * processes. So it need store/restore registers state by pairs to do not
 * destroy quad pointers
 */

#ifdef	CONFIG_GREGS_CONTEXT
/* Pair of global registers used by kernel:			*/
#define	KERNEL_GREGS_PAIRS_START	GUEST_VCPU_STATE_GREG	/* %dg16 */
/* Pair of global registers to point to current structures:	*/
/*	current & current_thread_info()				*/
#define	CURRENT_GREGS_PAIR_LO		GUEST_VCPU_STATE_GREG	/* %dg16 */
#define	CURRENT_GREGS_PAIR_HI		CURRENT_TASK_GREG	/* %dg17 */
#define	CURRENT_GREGS_PAIRS_NUM		1	/* one pair:	*/
						/* low: thread info */
						/* high: task structure */
#define	CURRENT_GREGS_PAIRS_SIZE		/* one pair of */	\
						/* two registers */	\
		(CURRENT_GREGS_PAIRS_NUM * 2)
#define	GUEST_VCPU_STATE_GREGS_PAIRS_INDEX	/* g[0] */	\
		(GUEST_VCPU_STATE_GREG - KERNEL_GREGS_PAIRS_START)
#define	CURRENT_TASK_GREGS_PAIRS_INDEX		/* g[1] */	\
		(CURRENT_TASK_GREG - KERNEL_GREGS_PAIRS_START)
#define	CURRENT_GREGS_PAIRS_INDEX_LO	GUEST_VCPU_STATE_GREGS_PAIRS_INDEX
#define	CURRENT_GREGS_PAIRS_INDEX_HI	CURRENT_TASK_GREGS_PAIRS_INDEX
/*	raw_smp_processor_id & __my_cpu_offset				*/
#define	CPU_GREGS_PAIR_LO		MY_CPU_OFFSET_GREG	/* %dg18 */
#define	CPU_GREGS_PAIR_HI		SMP_CPU_ID_GREG		/* %dg19 */
#define	CPU_GREGS_PAIRS_NUM		1	/* one pair:	*/
						/* low: my per cpu offset */
						/* high: CPU ID */
#define	CPU_GREGS_PAIRS_SIZE			/* one pair of */	\
						/* two registers */	\
		(CPU_GREGS_PAIRS_NUM * 2)
#define	MY_CPU_OFFSET_GREGS_PAIRS_INDEX		/* g[2] */	\
		(MY_CPU_OFFSET_GREG - KERNEL_GREGS_PAIRS_START)
#define	SMP_CPU_ID_GREGS_PAIRS_INDEX		/* g[3] */	\
		(SMP_CPU_ID_GREG - KERNEL_GREGS_PAIRS_START)
#define	CPU_GREGS_PAIRS_INDEX_LO	MY_CPU_OFFSET_GREGS_PAIRS_INDEX
#define	CPU_GREGS_PAIRS_INDEX_HI	SMP_CPU_ID_GREGS_PAIRS_INDEX

#define	NATIVE_KERNEL_GREGS_PAIRS_NUM	\
		(CURRENT_GREGS_PAIRS_NUM + CPU_GREGS_PAIRS_NUM)
#define	NATIVE_KERNEL_GREGS_PAIRS_SIZE	\
		(CURRENT_GREGS_PAIRS_SIZE + CPU_GREGS_PAIRS_SIZE)
#else	/* ! CONFIG_GREGS_CONTEXT */
#define	NATIVE_KERNEL_GREGS_PAIRS_NUM	0
#define	NATIVE_KERNEL_GREGS_PAIRS_SIZE	0
#endif	/* CONFIG_GREGS_CONTEXT */

#ifdef	CONFIG_VIRTUALIZATION
/* Pair of global registers used by host to support virtualization	*/
#define	HOST_GREGS_PAIRS_START		GUEST_VCPU_STATE_GREG	/* %dg16 */
/* VCPU state pointer is used always for virtualization support */
/* so it need be into starting pair */
#define	VCPU_STATE_GREGS_PAIR_LO	GUEST_VCPU_STATE_GREG	/* %dg16 */
#define	VCPU_STATE_GREGS_PAIR_HI	CURRENT_TASK_GREG	/* %dg17 */
#define	VCPU_STATE_GREGS_PAIRS_NUM	1	/* one pair:	*/
						/* low: kvm_vcpu_state */
						/* high: current task */
#define	VCPU_STATE_GREGS_PAIRS_SIZE		/* one pair of */	\
						/* two registers */	\
		(VCPU_STATE_GREGS_PAIRS_NUM * 2)
#define	VCPU_STATE_GREGS_PAIRS_INDEX		/* g[0] */	\
		(GUEST_VCPU_STATE_GREG - HOST_GREGS_PAIRS_START)
#define	VCPU_STATE_GREGS_PAIRS_HI_INDEX		/* g[1] */	\
		(CURRENT_TASK_GREG - HOST_GREGS_PAIRS_START)

/* indexes of global registers for virtualization in structure */
/* guest_gregs->g[] */
#define	HOST_VCPU_STATE_GREGS_PAIRS_INDEX_LO	/* g[0] */	\
		VCPU_STATE_GREGS_PAIRS_INDEX
#define	HOST_VCPU_STATE_GREGS_PAIRS_INDEX_HI	/* g[1] */	\
		VCPU_STATE_GREGS_PAIRS_HI_INDEX

#define	HOST_KERNEL_GREGS_PAIRS_NUM	VCPU_STATE_GREGS_PAIRS_NUM
#define	HOST_KERNEL_GREGS_PAIRS_SIZE	VCPU_STATE_GREGS_PAIRS_SIZE
#else	/* ! CONFIG_VIRTUALIZATION */
#define	HOST_KERNEL_GREGS_PAIRS_NUM	0
#define	HOST_KERNEL_GREGS_PAIRS_SIZE	0
#endif	/* CONFIG_VIRTUALIZATION */

/* real number & size of global registers pairs used by kernel */
/* in accordance with config and execution mode */
#define	KERNEL_GREGS_PAIRS_NUM		NATIVE_KERNEL_GREGS_PAIRS_NUM
#define	KERNEL_GREGS_PAIRS_SIZE		NATIVE_KERNEL_GREGS_PAIRS_SIZE

#endif /* __KERNEL__ */
#endif /* _E2K_GLOB_REGS_H */
