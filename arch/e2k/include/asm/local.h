#pragma once

#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <asm/atomic.h>

/*
 * A signed long type for operations which are atomic for a single CPU.
 * Usually used in combination with per-cpu variables.
 */

/* Use relaxed atomics if they are available */
#if CONFIG_CPU_ISET >= 5

# include <asm-generic/local.h>

/* Default implementation uses READ_ONCE and WRITE_ONCE
 * which are too slow on e2k because of "volatile" */
# undef __local_inc
# undef __local_dec
# undef __local_add
# undef __local_sub

#else

typedef struct { long counter; } __attribute__ ((aligned)) local_t;

# define LOCAL_INIT(i)	{ (i) }

# define local_read(l)	((l)->counter)
# define local_set(l, i) (((l)->counter) = (i))

/*
 * local_add - add long to local variable
 * @i: long value to add
 * @l: pointer of type local_t
 */
static inline void local_add(long i, local_t *l)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	l->counter += i;
	raw_all_irq_restore(flags);
}

/*
 * local_sub - sub long from local variable
 * @i: long value to sub
 * @l: pointer of type local_t
 */
static inline void local_sub(long i, local_t *l)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	l->counter -= i;
	raw_all_irq_restore(flags);
}

# define local_inc(l)	local_add(1,l)
# define local_dec(l)	local_sub(1,l)

/*
 * local_add_return - add long to local variable and return the result
 * @i: long value to add
 * @l: pointer of type local_t
 */
static inline long local_add_return(long i, local_t *l)
{
	unsigned long flags;
	register long result;

	raw_all_irq_save(flags);
	l->counter += i;
	result = l->counter;
	raw_all_irq_restore(flags);

	return result;
}

/*
 * local_sub_return - sub long from local variable and return the result
 * @i: long value to sub
 * @l: pointer of type local_t
 */
static inline long local_sub_return(long i, local_t *l)
{
	unsigned long flags;
	register long result;

	raw_all_irq_save(flags);
	l->counter -= i;
	result = l->counter;
	raw_all_irq_restore(flags);

	return result;
}

# define local_add_negative(i, l) (local_add_return(i,l) < 0)
# define local_sub_and_test(i, l) (local_sub_return(i,l) == 0)
# define local_inc_and_test(l) (local_add_return(1,l) == 0)
# define local_dec_and_test(l) (local_sub_return(1,l) == 0)

static inline long local_cmpxchg(local_t *l, long o, long n)
{
	unsigned long flags;
	register long result;

	raw_all_irq_save(flags);
	result = l->counter;
	if (result == o)
		l->counter = n;
	raw_all_irq_restore(flags);

	return result;
}

static inline long local_xchg(local_t *l, long n)
{
	unsigned long flags;
	register long result;

	raw_all_irq_save(flags);
	result = l->counter;
	l->counter = n;
	raw_all_irq_restore(flags);

	return result;
}

/**
 * local_add_unless - add unless the number is a given value
 * @l: pointer of type local_t
 * @a: the amount to add to l...
 * @u: ...unless l is equal to u.
 *
 * Atomically adds @a to @l, so long as it was not @u.
 * Returns non-zero if @l was not @u, and zero otherwise.
 */
static inline int local_add_unless(local_t *l, long a, long u)
{
	unsigned long flags;
	register long result;

	raw_all_irq_save(flags);
	if (l->counter == u) {
		result = 0;
	} else {
		l->counter += a;
		result = 1;
	}
	raw_all_irq_restore(flags);

	return result;
}

# define local_inc_return(l)	local_add_return(1, l)
# define local_dec_return(l)	local_sub_return(1, l)

# define local_inc_not_zero(l)	local_add_unless((l), 1, 0)

#endif

/* Non-atomic variants, ie. preemption disabled and won't be touched
 * in interrupt, etc. */
#define __local_inc(l)		((l)->a.counter++)
#define __local_dec(l)		((l)->a.counter++)
#define __local_add(i, l)	((l)->a.counter += (i))
#define __local_sub(i, l)	((l)->a.counter -= (i))

#ifdef CONFIG_HAVE_FTRACE_NMI_ENTER
# warning For the sake of atomicity nmie's must be disabled here along with ie's
#endif

