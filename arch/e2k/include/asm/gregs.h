/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_GREGS_H
#define _E2K_GREGS_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/machdep.h>
#include <asm/glob_regs.h>
#include <asm/ptrace.h>

/*
 * Save new value of gN and set current pointer into these register
 * to can use macroses current & current_thread_info()
 */
#define	SET_CURRENTS_GREGS(__task)					\
({									\
	E2K_SET_DGREG_NV(CURRENT_TASK_GREG, (__task));			\
})
#define	SET_SMP_CPUS_GREGS(__cpu, __per_cpu_off)			\
({									\
	E2K_SET_DGREG_NV(SMP_CPU_ID_GREG, (__cpu));			\
	E2K_SET_DGREG_NV(MY_CPU_OFFSET_GREG, (__per_cpu_off));		\
})
#define	SET_KERNEL_GREGS(__task, __cpu, __per_cpu_off)			\
({									\
	SET_CURRENTS_GREGS(__task);					\
	SET_SMP_CPUS_GREGS(__cpu, __per_cpu_off);			\
})
#define	ONLY_SET_CURRENTS_GREGS(__ti)					\
({									\
	SET_CURRENTS_GREGS(thread_info_task(__ti));			\
})
#define	ONLY_SAVE_KERNEL_CURRENTS_GREGS(task__)				\
({									\
	(task__) = NATIVE_GET_UNTEGGED_DGREG(CURRENT_TASK_GREG);	\
})
#ifdef	CONFIG_SMP
#define	ONLY_SAVE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__)		\
({									\
	(cpu_id__) = NATIVE_GET_UNTEGGED_DGREG(SMP_CPU_ID_GREG);	\
	(cpu_off__) = NATIVE_GET_UNTEGGED_DGREG(MY_CPU_OFFSET_GREG);	\
})
#else	/* ! CONFIG_SMP */
#define	ONLY_SAVE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__)
#endif	/* CONFIG_SMP */
#define	ONLY_SAVE_KERNEL_GREGS(task__, cpu_id__, cpu_off__)		\
({									\
	ONLY_SAVE_KERNEL_CURRENTS_GREGS(task__);			\
	ONLY_SAVE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__);		\
})

#define	ONLY_RESTORE_KERNEL_CURRENTS_GREGS(task__)			\
({									\
	NATIVE_SET_DGREG(CURRENT_TASK_GREG, task__);			\
})
#ifdef	CONFIG_SMP
#define	ONLY_RESTORE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__)		\
({									\
	NATIVE_SET_DGREG(SMP_CPU_ID_GREG, cpu_id__);			\
	NATIVE_SET_DGREG(MY_CPU_OFFSET_GREG, cpu_off__);		\
})
#else	/* ! CONFIG_SMP */
#define	ONLY_RESTORE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__)
#endif	/* CONFIG_SMP */
#define	ONLY_RESTORE_KERNEL_GREGS(task__, cpu_id__, cpu_off__)\
({									\
	ONLY_RESTORE_KERNEL_CURRENTS_GREGS(task__);			\
	ONLY_RESTORE_KERNEL_SMP_CPUS_GREGS(cpu_id__, cpu_off__);	\
})

#ifdef	CONFIG_SMP
#define	ONLY_SET_SMP_CPUS_GREGS(__ti)					\
({									\
	long __cpu = task_cpu(thread_info_task(__ti));			\
									\
	SET_SMP_CPUS_GREGS(__cpu, per_cpu_offset(__cpu));		\
})
#else	/* ! CONFIG_SMP */
#define	ONLY_SET_SMP_CPUS_GREGS(__ti)
#endif	/* CONFIG_SMP */

#define	ONLY_SET_KERNEL_GREGS(__ti)					\
({									\
	ONLY_SET_CURRENTS_GREGS(__ti);					\
	ONLY_SET_SMP_CPUS_GREGS(__ti);					\
})

#define	CLEAR_KERNEL_GREGS()						\
({									\
	SET_KERNEL_GREGS(0, 0, 0);					\
})

/*
 * global registers used as pointers to current task & thread info
 * must be restored and current & current_thread_info() can not be
 * used from now
 */
#define	ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(__k_gregs, task__)		\
({									\
	(task__) = (__k_gregs)->g[CURRENT_TASK_GREGS_PAIRS_INDEX].base;	\
})
#ifdef	CONFIG_SMP
#define	ONLY_COPY_FROM_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__) \
({									     \
	(cpu_id__) = (__k_gregs)->g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base;	     \
	(cpu_off__) = (__k_gregs)->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base;  \
})
#else	/* ! CONFIG_SMP */
#define	ONLY_COPY_FROM_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__)
#endif	/* CONFIG_SMP */
#define	ONLY_COPY_FROM_KERNEL_GREGS(__k_gregs, task__, cpu_id__, cpu_off__)   \
({									      \
	ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(__k_gregs, task__);		      \
	ONLY_COPY_FROM_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__); \
})

#define	ONLY_COPY_TO_KERNEL_CURRENT_GREGS(__k_gregs, task__)		\
({									\
	(__k_gregs)->g[CURRENT_TASK_GREGS_PAIRS_INDEX].base = (task__);	\
})
#ifdef	CONFIG_SMP
#define	ONLY_COPY_TO_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__) \
({									\
	(__k_gregs)->g[SMP_CPU_ID_GREGS_PAIRS_INDEX].base = (cpu_id__);	\
	(__k_gregs)->g[MY_CPU_OFFSET_GREGS_PAIRS_INDEX].base = (cpu_off__); \
})
#else	/* ! CONFIG_SMP */
#define	ONLY_COPY_TO_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__)
#endif	/* CONFIG_SMP */
#define	ONLY_COPY_TO_KERNEL_GREGS(__k_gregs, task__, cpu_id__, cpu_off__)   \
({									    \
	ONLY_COPY_TO_KERNEL_CURRENT_GREGS(__k_gregs, task__);		    \
	ONLY_COPY_TO_KERNEL_SMP_CPUS_GREGS(__k_gregs, cpu_id__, cpu_off__); \
})
#define	CLEAR_KERNEL_GREGS_COPY(__ti)	\
		ONLY_COPY_TO_KERNEL_GREGS(&(__ti)->k_gregs, 0, 0, 0)

#if !defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */

#define	CLEAR_KERNEL_GREGS_IN_SYSCALL(...) \
	NATIVE_SET_GREGS_EMPTY(false, true, cpu_has(CPU_FEAT_QPREG))

 #ifdef	CONFIG_VIRTUALIZATION
  /* it is native host kernel with virtualization support */
  #include <asm/kvm/gregs.h>
 #endif	/* CONFIG_VIRTUALIZATION */
#endif	/* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_KERNEL */

static inline void copy_k_gregs_to_gregs(struct e2k_gregs *dst,
		const struct local_gregs *src)
{
	tagged_memcpy_8(&dst->g[KERNEL_GREGS_PAIRS_START], src->g,
			sizeof(src->g));
}

static inline void copy_scratch_gregs_from_local(struct scratch_gregs *scratch,
		const struct local_gregs *local)
{
	tagged_memcpy_8(&scratch->g[0], &local->g[KERNEL_GREGS_MAX_NUM],
			sizeof(scratch->g) + __must_be_array(scratch->g));
}

static inline void copy_local_gregs(struct local_gregs *dst, const struct local_gregs *src)
{
	tagged_memcpy_8(dst->g, src->g, sizeof(dst->g) + __must_be_array(dst->g));
	dst->bgr = src->bgr;
}

static inline void copy_scratch_gregs(struct scratch_gregs *dst, const struct scratch_gregs *src)
{
	tagged_memcpy_8(dst->g, src->g, sizeof(dst->g) + __must_be_array(dst->g));
}

#endif
