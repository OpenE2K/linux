#ifndef _E2K_ATOMIC_
#define _E2K_ATOMIC_

#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/atomic_api.h>

#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define atomic_read(v)		READ_ONCE((v)->counter)
#define atomic64_read(v)	READ_ONCE((v)->counter)

#define atomic_set(v, i)	WRITE_ONCE(((v)->counter), (i))
#define atomic64_set(v, i)	WRITE_ONCE(((v)->counter), (i))

static inline void atomic_and(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "ands", RELAXED_MB);
}

static inline void atomic64_and(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "andd", RELAXED_MB);
}

#define atomic_andnot atomic_andnot
static inline void atomic_andnot(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "andns", RELAXED_MB);
}

#define atomic64_andnot atomic64_andnot
static inline void atomic64_andnot(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "andnd", RELAXED_MB);
}

static inline void atomic_or(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "ors", RELAXED_MB);
}

static inline void atomic64_or(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "ord", RELAXED_MB);
}

static inline void atomic_xor(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "xors", RELAXED_MB);
}

static inline void atomic64_xor(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "xord", RELAXED_MB);
}

static inline void atomic_add(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "adds", RELAXED_MB);
}

static inline void atomic64_add(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "addd", RELAXED_MB);
}

static inline void atomic_sub(int incr, atomic_t *val)
{
	__api_atomic_op(incr, &val->counter, w, "subs", RELAXED_MB);
}

static inline void atomic64_sub(__s64 incr, atomic64_t *val)
{
	__api_atomic_op(incr, &val->counter, d, "subd", RELAXED_MB);
}

#define __atomic_add_return(v, p, mem_model) \
	__api_atomic_op((int) (v), &(p)->counter, w, "adds", mem_model)
#define atomic_add_return_relaxed(v, p) __atomic_add_return((v), (p), RELAXED_MB)
#define atomic_add_return_acquire(v, p) __atomic_add_return((v), (p), ACQUIRE_MB)
#define atomic_add_return_release(v, p) __atomic_add_return((v), (p), RELEASE_MB)
#define atomic_add_return(v, p)		__atomic_add_return((v), (p), STRONG_MB)
#define atomic_add_return_lock(v, p)	__atomic_add_return((v), (p), LOCK_MB)

#define __atomic64_add_return(v, p, mem_model) \
	__api_atomic_op((__s64) (v), &(p)->counter, d, "addd", mem_model)
#define atomic64_add_return_relaxed(v, p) __atomic64_add_return((v), (p), RELAXED_MB)
#define atomic64_add_return_acquire(v, p) __atomic64_add_return((v), (p), ACQUIRE_MB)
#define atomic64_add_return_release(v, p) __atomic64_add_return((v), (p), RELEASE_MB)
#define atomic64_add_return(v, p)	  __atomic64_add_return((v), (p), STRONG_MB)

#define __atomic_sub_return(v, p, mem_model) \
	__api_atomic_op((int) (v), &(p)->counter, w, "subs", mem_model)
#define atomic_sub_return_relaxed(v, p) __atomic_sub_return((v), (p), RELAXED_MB)
#define atomic_sub_return_acquire(v, p) __atomic_sub_return((v), (p), ACQUIRE_MB)
#define atomic_sub_return_release(v, p) __atomic_sub_return((v), (p), RELEASE_MB)
#define atomic_sub_return(v, p)		__atomic_sub_return((v), (p), STRONG_MB)

#define __atomic64_sub_return(v, p, mem_model) \
	__api_atomic_op((__s64) (v), &(p)->counter, d, "subd", mem_model)
#define atomic64_sub_return_relaxed(v, p) __atomic64_sub_return((v), (p), RELAXED_MB)
#define atomic64_sub_return_acquire(v, p) __atomic64_sub_return((v), (p), ACQUIRE_MB)
#define atomic64_sub_return_release(v, p) __atomic64_sub_return((v), (p), RELEASE_MB)
#define atomic64_sub_return(v, p)	  __atomic64_sub_return((v), (p), STRONG_MB)

#define __atomic_fetch_add(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "adds", mem_model)
#define atomic_fetch_add_relaxed(v, p) __atomic_fetch_add((v), (p), RELAXED_MB)
#define atomic_fetch_add_acquire(v, p) __atomic_fetch_add((v), (p), ACQUIRE_MB)
#define atomic_fetch_add_release(v, p) __atomic_fetch_add((v), (p), RELEASE_MB)
#define atomic_fetch_add(v, p)	       __atomic_fetch_add((v), (p), STRONG_MB)

#define __atomic64_fetch_add(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "addd", mem_model)
#define atomic64_fetch_add_relaxed(v, p) __atomic64_fetch_add((v), (p), RELAXED_MB)
#define atomic64_fetch_add_acquire(v, p) __atomic64_fetch_add((v), (p), ACQUIRE_MB)
#define atomic64_fetch_add_release(v, p) __atomic64_fetch_add((v), (p), RELEASE_MB)
#define atomic64_fetch_add(v, p)	 __atomic64_fetch_add((v), (p), STRONG_MB)

#define __atomic_fetch_sub(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "subs", mem_model)
#define atomic_fetch_sub_relaxed(v, p) __atomic_fetch_sub((v), (p), RELAXED_MB)
#define atomic_fetch_sub_acquire(v, p) __atomic_fetch_sub((v), (p), ACQUIRE_MB)
#define atomic_fetch_sub_release(v, p) __atomic_fetch_sub((v), (p), RELEASE_MB)
#define atomic_fetch_sub(v, p)	       __atomic_fetch_sub((v), (p), STRONG_MB)

#define __atomic64_fetch_sub(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "subd", mem_model)
#define atomic64_fetch_sub_relaxed(v, p) __atomic64_fetch_sub((v), (p), RELAXED_MB)
#define atomic64_fetch_sub_acquire(v, p) __atomic64_fetch_sub((v), (p), ACQUIRE_MB)
#define atomic64_fetch_sub_release(v, p) __atomic64_fetch_sub((v), (p), RELEASE_MB)
#define atomic64_fetch_sub(v, p)	 __atomic64_fetch_sub((v), (p), STRONG_MB)

#define __atomic_fetch_or(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "ors", mem_model)
#define atomic_fetch_or_relaxed(v, p) __atomic_fetch_or((v), (p), RELAXED_MB)
#define atomic_fetch_or_acquire(v, p) __atomic_fetch_or((v), (p), ACQUIRE_MB)
#define atomic_fetch_or_release(v, p) __atomic_fetch_or((v), (p), RELEASE_MB)
#define atomic_fetch_or(v, p)	      __atomic_fetch_or((v), (p), STRONG_MB)

#define __atomic64_fetch_or(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "ord", mem_model)
#define atomic64_fetch_or_relaxed(v, p) __atomic64_fetch_or((v), (p), RELAXED_MB)
#define atomic64_fetch_or_acquire(v, p) __atomic64_fetch_or((v), (p), ACQUIRE_MB)
#define atomic64_fetch_or_release(v, p) __atomic64_fetch_or((v), (p), RELEASE_MB)
#define atomic64_fetch_or(v, p)		__atomic64_fetch_or((v), (p), STRONG_MB)

#define __atomic_fetch_and(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "ands", mem_model)
#define atomic_fetch_and_relaxed(v, p) __atomic_fetch_and((v), (p), RELAXED_MB)
#define atomic_fetch_and_acquire(v, p) __atomic_fetch_and((v), (p), ACQUIRE_MB)
#define atomic_fetch_and_release(v, p) __atomic_fetch_and((v), (p), RELEASE_MB)
#define atomic_fetch_and(v, p)	       __atomic_fetch_and((v), (p), STRONG_MB)

#define __atomic64_fetch_and(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "andd", mem_model)
#define atomic64_fetch_and_relaxed(v, p) __atomic64_fetch_and((v), (p), RELAXED_MB)
#define atomic64_fetch_and_acquire(v, p) __atomic64_fetch_and((v), (p), ACQUIRE_MB)
#define atomic64_fetch_and_release(v, p) __atomic64_fetch_and((v), (p), RELEASE_MB)
#define atomic64_fetch_and(v, p)	 __atomic64_fetch_and((v), (p), STRONG_MB)

#define __atomic_fetch_andnot(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "andns", mem_model)
#define atomic_fetch_andnot_relaxed(v, p) __atomic_fetch_andnot((v), (p), RELAXED_MB)
#define atomic_fetch_andnot_acquire(v, p) __atomic_fetch_andnot((v), (p), ACQUIRE_MB)
#define atomic_fetch_andnot_release(v, p) __atomic_fetch_andnot((v), (p), RELEASE_MB)
#define atomic_fetch_andnot(v, p)	  __atomic_fetch_andnot((v), (p), STRONG_MB)

#define __atomic64_fetch_andnot(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "andnd", mem_model)
#define atomic64_fetch_andnot_relaxed(v, p) __atomic64_fetch_andnot((v), (p), RELAXED_MB)
#define atomic64_fetch_andnot_acquire(v, p) __atomic64_fetch_andnot((v), (p), ACQUIRE_MB)
#define atomic64_fetch_andnot_release(v, p) __atomic64_fetch_andnot((v), (p), RELEASE_MB)
#define atomic64_fetch_andnot(v, p)	    __atomic64_fetch_andnot((v), (p), STRONG_MB)

#define __atomic_fetch_xor(v, p, mem_model) \
	__api_atomic_fetch_op((int) (v), &(p)->counter, w, "xors", mem_model)
#define atomic_fetch_xor_relaxed(v, p) __atomic_fetch_xor((v), (p), RELAXED_MB)
#define atomic_fetch_xor_acquire(v, p) __atomic_fetch_xor((v), (p), ACQUIRE_MB)
#define atomic_fetch_xor_release(v, p) __atomic_fetch_xor((v), (p), RELEASE_MB)
#define atomic_fetch_xor(v, p)	       __atomic_fetch_xor((v), (p), STRONG_MB)

#define __atomic64_fetch_xor(v, p, mem_model) \
	__api_atomic_fetch_op((__s64) (v), &(p)->counter, d, "xord", mem_model)
#define atomic64_fetch_xor_relaxed(v, p) __atomic64_fetch_xor((v), (p), RELAXED_MB)
#define atomic64_fetch_xor_acquire(v, p) __atomic64_fetch_xor((v), (p), ACQUIRE_MB)
#define atomic64_fetch_xor_release(v, p) __atomic64_fetch_xor((v), (p), RELEASE_MB)
#define atomic64_fetch_xor(v, p)	 __atomic64_fetch_xor((v), (p), STRONG_MB)

#define __atomic_xchg(p, v, mem_model) \
	(int)__api_xchg_return((int) (v), &(p)->counter, w, mem_model)
#define atomic_xchg_relaxed(p, v) __atomic_xchg((p), (v), RELAXED_MB)
#define atomic_xchg_acquire(p, v) __atomic_xchg((p), (v), ACQUIRE_MB)
#define atomic_xchg_release(p, v) __atomic_xchg((p), (v), RELEASE_MB)
#define atomic_xchg(p, v)	  __atomic_xchg((p), (v), STRONG_MB)

#define __atomic64_xchg(p, v, mem_model) \
	__api_xchg_return((__s64) (v), &(p)->counter, d, mem_model)
#define atomic64_xchg_relaxed(p, v) __atomic64_xchg((p), (v), RELAXED_MB)
#define atomic64_xchg_acquire(p, v) __atomic64_xchg((p), (v), ACQUIRE_MB)
#define atomic64_xchg_release(p, v) __atomic64_xchg((p), (v), RELEASE_MB)
#define atomic64_xchg(p, v)	    __atomic64_xchg((p), (v), STRONG_MB)

#define __atomic_cmpxchg(p, o, n, mem_model) \
	(int)__api_cmpxchg_word_return((int) (o), (int) (n), \
				  &(p)->counter, mem_model)
#define atomic_cmpxchg_relaxed(p, o, n) __atomic_cmpxchg((p), (o), (n), RELAXED_MB)
#define atomic_cmpxchg_acquire(p, o, n) __atomic_cmpxchg((p), (o), (n), ACQUIRE_MB)
#define atomic_cmpxchg_release(p, o, n) __atomic_cmpxchg((p), (o), (n), RELEASE_MB)
#define atomic_cmpxchg(p, o, n)		__atomic_cmpxchg((p), (o), (n), STRONG_MB)
#define atomic_cmpxchg_lock(p, o, n)	__atomic_cmpxchg((p), (o), (n), LOCK_MB)

#define __atomic64_cmpxchg(p, o, n, mem_model) \
	__api_cmpxchg_dword_return((__s64) (o), (__s64) (n), \
				   &(p)->counter, mem_model)
#define atomic64_cmpxchg_relaxed(p, o, n) __atomic64_cmpxchg((p), (o), (n), RELAXED_MB)
#define atomic64_cmpxchg_acquire(p, o, n) __atomic64_cmpxchg((p), (o), (n), ACQUIRE_MB)
#define atomic64_cmpxchg_release(p, o, n) __atomic64_cmpxchg((p), (o), (n), RELEASE_MB)
#define atomic64_cmpxchg(p, o, n)	  __atomic64_cmpxchg((p), (o), (n), STRONG_MB)
#define atomic64_cmpxchg_lock(p, o, n)	  __atomic64_cmpxchg((p), (o), (n), LOCK_MB)

#define atomic_long_cmpxchg_lock(p, o, n) atomic64_cmpxchg_lock((p), (o), (n))

#define atomic_inc_unless_negative atomic_inc_unless_negative
static inline bool atomic_inc_unless_negative(atomic_t *p)
{
	return __api_atomic32_fetch_inc_unless_negative(&p->counter) >= 0;
}

#define atomic64_inc_unless_negative atomic64_inc_unless_negative
static inline bool atomic64_inc_unless_negative(atomic64_t *p)
{
	return __api_atomic64_fetch_inc_unless_negative(&p->counter) >= 0;
}

#define atomic_dec_unless_positive atomic_dec_unless_positive
static inline bool atomic_dec_unless_positive(atomic_t *p)
{
	return __api_atomic32_fetch_dec_unless_positive(&p->counter) <= 0;
}

#define atomic64_dec_unless_positive atomic64_dec_unless_positive
static inline bool atomic64_dec_unless_positive(atomic64_t *p)
{
	return __api_atomic64_fetch_dec_unless_positive(&p->counter) <= 0;
}

/**
 * atomic_dec_if_positive - decrement by 1 if old value positive
 * @p: pointer of type atomic_t
 *
 * The function returns the old value of *p minus 1, even if
 * the atomic variable, v, was not decremented.
 */
#define atomic_dec_if_positive atomic_dec_if_positive
static inline int atomic_dec_if_positive(atomic_t *p)
{
	return __api_atomic32_fetch_dec_if_positive(&p->counter) - 1;
}

#define atomic64_dec_if_positive atomic64_dec_if_positive
static inline s64 atomic64_dec_if_positive(atomic64_t *p)
{
	return __api_atomic64_fetch_dec_if_positive(&p->counter) - 1;
}

/**
 * atomic_fetch_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns original value of @v
 */
#define atomic_fetch_add_unless atomic_fetch_add_unless
static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
	return __api_atomic32_fetch_add_unless(a, &v->counter, u);
}

#define atomic64_fetch_add_unless atomic64_fetch_add_unless
static inline s64 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
{
	return __api_atomic64_fetch_add_unless(a, &v->counter, u);
}

#define atomic_try_cmpxchg atomic_try_cmpxchg
static inline bool atomic_try_cmpxchg(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic_try_cmpxchg_acquire atomic_try_cmpxchg_acquire
static inline bool atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg_acquire(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic_try_cmpxchg_release atomic_try_cmpxchg_release
static inline bool atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg_release(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic_try_cmpxchg_relaxed atomic_try_cmpxchg_relaxed
static inline bool atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg_relaxed(v, o, new);
	*old = r;
	return likely(r == o);
}

static __always_inline bool atomic_try_cmpxchg_lock(atomic_t *v, int *old, int new)
{
	int r, o = *old;
	r = atomic_cmpxchg_lock(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic64_try_cmpxchg atomic64_try_cmpxchg
static inline bool atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
{
	s64 r, o = *old;
	r = atomic64_cmpxchg(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic64_try_cmpxchg_acquire atomic64_try_cmpxchg_acquire
static inline bool atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
{
	s64 r, o = *old;
	r = atomic64_cmpxchg_acquire(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic64_try_cmpxchg_release atomic64_try_cmpxchg_release
static inline bool atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
{
	s64 r, o = *old;
	r = atomic64_cmpxchg_release(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic64_try_cmpxchg_relaxed atomic64_try_cmpxchg_relaxed
static inline bool atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
{
	s64 r, o = *old;
	r = atomic64_cmpxchg_relaxed(v, o, new);
	*old = r;
	return likely(r == o);
}

static inline bool atomic64_try_cmpxchg_lock(atomic64_t *v, s64 *old, s64 new)
{
	s64 r, o = *old;
	r = atomic64_cmpxchg_lock(v, o, new);
	*old = r;
	return likely(r == o);
}

#define atomic_long_try_cmpxchg_lock(p, o, n) atomic64_try_cmpxchg_lock((p), (s64 *) (o), (n))

#endif /* _E2K_ATOMIC_ */
