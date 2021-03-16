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
#define	NATIVE_SAVE_KERNEL_GREGS_AND_SET(__ti)				\
({									\
	machine.save_kernel_gregs(&(__ti)->k_gregs);			\
	ONLY_SET_KERNEL_GREGS(__ti);					\
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

#define	NATIVE_RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)		\
({									\
	thread_info_t *__ti = (thread_info);				\
									\
	NATIVE_RESTORE_KERNEL_GREG(__ti->k_gregs.g,			\
		GUEST_VCPU_STATE_GREGS_PAIRS_INDEX,			\
		CURRENT_TASK_GREGS_PAIRS_INDEX,				\
		MY_CPU_OFFSET_GREGS_PAIRS_INDEX,			\
		SMP_CPU_ID_GREGS_PAIRS_INDEX,				\
			GUEST_VCPU_STATE_GREG, CURRENT_TASK_GREG,	\
			MY_CPU_OFFSET_GREG, SMP_CPU_ID_GREG);		\
})

/* User global registers, used by kernel, keep into thread info structure */
/* and save to/restore from while enter to/return from kernel */
#define	CLEAR_GREGS_COPY_FROM_CURRENTS(thread_info)			\
({									\
	thread_info_t *__ti = (thread_info);				\
									\
	__ti->k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].base = 0;	\
	__ti->k_gregs.g[GUEST_VCPU_STATE_GREGS_PAIRS_INDEX].ext = 0;	\
	__ti->k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].base = 0;	\
	__ti->k_gregs.g[CURRENT_TASK_GREGS_PAIRS_INDEX].ext = 0;	\
})

#if !defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */

#define	SAVE_KERNEL_GREGS_AND_SET(thread_info)	\
		NATIVE_SAVE_KERNEL_GREGS_AND_SET(thread_info)
#define	RESTORE_KERNEL_GREGS_AND_FREE(thread_info)	\
		NATIVE_RESTORE_KERNEL_GREGS(&(thread_info)->k_gregs)
#define	RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)	\
		NATIVE_RESTORE_KERNEL_GREGS_IN_SYSCALL(thread_info)
 #ifdef	CONFIG_VIRTUALIZATION
  /* it is native host kernel with virtualization support */
  #include <asm/kvm/gregs.h>
 #endif	/* CONFIG_VIRTUALIZATION */
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

static inline void copy_k_gregs_to_gregs(struct global_regs *dst,
		const struct kernel_gregs *src)
{
	tagged_memcpy_8(&dst->g[KERNEL_GREGS_PAIRS_START], src->g,
			sizeof(src->g));
}

static inline void copy_k_gregs_to_k_gregs(struct kernel_gregs *dst,
		const struct kernel_gregs *src)
{
	tagged_memcpy_8(dst->g, src->g, sizeof(src->g));
}

static inline void get_k_gregs_from_gregs(struct kernel_gregs *dst,
		const struct global_regs *src)
{
	tagged_memcpy_8(dst->g, &src->g[KERNEL_GREGS_PAIRS_START],
			sizeof(dst->g));
}

static inline void copy_k_gregs_to_l_gregs(struct local_gregs *dst,
		const struct kernel_gregs *src)
{
	BUG_ON(KERNEL_GREGS_PAIRS_START < LOCAL_GREGS_START);
	tagged_memcpy_8(&dst->g[KERNEL_GREGS_PAIRS_START - LOCAL_GREGS_START],
			src->g, sizeof(src->g));
}

static inline void get_k_gregs_from_l_regs(struct kernel_gregs *dst,
		const struct local_gregs *src)
{
	BUG_ON(KERNEL_GREGS_PAIRS_START < LOCAL_GREGS_START);
	tagged_memcpy_8(dst->g,
			&src->g[KERNEL_GREGS_PAIRS_START - LOCAL_GREGS_START],
			sizeof(dst->g));
}

#endif
