#pragma once

#include <linux/thread_info.h>

register unsigned long long __cpu_preempt_reg DO_ASM_GET_GREG_MEMONIC(
							SMP_CPU_ID_GREG);

#define PREEMPT_COUNTER_SHIFT 33ull

#define PREEMPT_NEED_RESCHED 0x100000000ull

#define PREEMPT_ENABLED	(0)

static __always_inline int preempt_count(void)
{
	return __cpu_preempt_reg >> PREEMPT_COUNTER_SHIFT;
}

/*
 * must be macros to avoid header recursion hell
 */
#define init_task_preempt_count(p) do { } while (0)

#define init_idle_preempt_count(p, cpu) do { \
	__cpu_preempt_reg = (u64) (u32) __cpu_preempt_reg; \
} while (0)

static __always_inline void set_preempt_need_resched(void)
{
	__cpu_preempt_reg |= PREEMPT_NEED_RESCHED;
}

static __always_inline void clear_preempt_need_resched(void)
{
	__cpu_preempt_reg &= ~PREEMPT_NEED_RESCHED;
}

static __always_inline bool test_preempt_need_resched(void)
{
	return __cpu_preempt_reg & PREEMPT_NEED_RESCHED;
}

/*
 * The various preempt_count set/add/sub methods
 *
 * Careful here: an interrupt can arrive at any moment and set or clear
 * the PREEMPT_NEED_RESCHED flag.  We want to change preempt_count
 * in a safe way so that the flag set in interrupt is not lost.
 */

static __always_inline void preempt_count_set(int pc)
{
	E2K_INSFD_ATOMIC(pc,
			31 /*shift*/ | (33 /*size*/  << 6) | (1 /*me1hi*/ << 13),
			__cpu_preempt_reg);
}


static __always_inline void __preempt_count_add(int val)
{
	E2K_ADDD_ATOMIC(__cpu_preempt_reg, (u64) (u32) val << PREEMPT_COUNTER_SHIFT);
}

static __always_inline void __preempt_count_sub(int val)
{
	E2K_SUBD_ATOMIC(__cpu_preempt_reg, (u64) (u32) val << PREEMPT_COUNTER_SHIFT);
}

static __always_inline bool __preempt_count_dec_and_test(void)
{
	u64 old;

	E2K_SUBD_ATOMIC__SHRD32(__cpu_preempt_reg, 1ull << PREEMPT_COUNTER_SHIFT, old);
#ifdef CONFIG_PREEMPT_LAZY
	if ((__cpu_preempt_reg >> 32ull) & ~1ull) /* as in arm64 */
		return false;
	if (current_thread_info()->preempt_lazy_count)
		return false;
	return test_thread_flag(TIF_NEED_RESCHED_LAZY);
#else
	return unlikely(old == 1);
#endif
}

static __always_inline void init_preempt_count_resched(int pc, int resched)
{
	__cpu_preempt_reg = (u64) (u32) __cpu_preempt_reg;
	preempt_count_set(pc);
	if (resched)
		set_preempt_need_resched();
}

/*
 * Returns true when we need to resched and can (barring IRQ state).
 */
static __always_inline bool should_resched(int preempt_offset)
{
#ifdef CONFIG_PREEMPT_LAZY
	u64 tmp_par = (u64) (u32) preempt_offset << 1;
	u64 tmp = __cpu_preempt_reg >> 32ull;

	if (tmp == tmp_par)
		return true;

	/* preempt count == 0 ? */
	tmp &= ~1ull;	/* ~PREEMPT_NEED_RESCHED */
	if (tmp != tmp_par)
		return false;
	if (current_thread_info()->preempt_lazy_count)
		return false;
	return test_thread_flag(TIF_NEED_RESCHED_LAZY);
#else
	return unlikely((__cpu_preempt_reg >> 32ull) ==
			(((u64) (u32) preempt_offset << 1) | 1));
#endif
}

#ifdef CONFIG_PREEMPTION
extern asmlinkage void preempt_schedule(void);
#define __preempt_schedule() preempt_schedule()
extern asmlinkage void preempt_schedule_notrace(void);
#define __preempt_schedule_notrace() preempt_schedule_notrace()
#endif /* CONFIG_PREEMPTION */

