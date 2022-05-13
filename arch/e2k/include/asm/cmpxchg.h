#ifndef ASM_E2K_CMPXCHG_H
#define ASM_E2K_CMPXCHG_H

#include <linux/compiler.h>
#include <asm/machdep.h>
#include <asm/e2k_api.h>
#include <asm/atomic_api.h>

/*
 * Non-existant functions to indicate usage errors at link time
 * (or compile-time if the compiler implements __compiletime_error().
 */
extern void __xchg_wrong_size(void)
	__compiletime_error("Bad argument size for xchg");
extern void __cmpxchg_wrong_size(void)
	__compiletime_error("Bad argument size for cmpxchg");

#define __xchg(ptr, val, mem_model) \
({ \
	volatile void *__x_ptr = (volatile void *) (ptr); \
	u64 __x_ret, __x_val = (u64) (val); \
	switch (sizeof(*(ptr))) { \
	case 1: \
		__x_ret = __api_xchg_return(__x_val, (volatile u8 *) __x_ptr, \
					    b, mem_model); \
		break; \
	case 2: \
		__x_ret = __api_xchg_return(__x_val, (volatile u16 *) __x_ptr, \
					    h, mem_model); \
		break; \
	case 4: \
		__x_ret = __api_xchg_return(__x_val, (volatile u32 *) __x_ptr, \
					    w, mem_model); \
		break; \
	case 8: \
		__x_ret = __api_xchg_return(__x_val, (volatile u64 *) __x_ptr, \
					    d, mem_model); \
		break; \
	default: \
		__x_ret = 0; \
		__xchg_wrong_size(); \
		break; \
	} \
	(__typeof__(*(ptr))) __x_ret; \
})
#define xchg_relaxed(ptr, v) __xchg((ptr), (v), RELAXED_MB)
#define xchg_acquire(ptr, v) __xchg((ptr), (v), ACQUIRE_MB)
#define xchg_release(ptr, v) __xchg((ptr), (v), RELEASE_MB)
#define xchg(ptr, v)	     __xchg((ptr), (v), STRONG_MB)

#define __cmpxchg(ptr, old, new, mem_model) \
({ \
	volatile void *__x_ptr = (volatile void *) (ptr); \
	u64 __x_ret, __x_old = (u64) (old), __x_new = (u64) (new); \
	switch (sizeof(*(ptr))) { \
	case 1: \
		__x_ret = __api_cmpxchg_return(__x_old, __x_new, \
			(volatile u8 *) __x_ptr, b, 0x4, mem_model); \
		break; \
	case 2: \
		__x_ret = __api_cmpxchg_return(__x_old, __x_new, \
			(volatile u16 *) __x_ptr, h, 0x5, mem_model); \
		break; \
	case 4: \
		__x_ret = __api_cmpxchg_word_return(__x_old, __x_new, \
			(volatile u32 *) __x_ptr, mem_model); \
		break; \
	case 8: \
		__x_ret = __api_cmpxchg_dword_return(__x_old, __x_new, \
			(volatile u64 *) __x_ptr, mem_model); \
		break; \
	default: \
		__x_ret = 0; \
		__cmpxchg_wrong_size(); \
		break; \
	} \
	(__typeof__(*(ptr))) __x_ret; \
})
#define cmpxchg_relaxed(ptr, o, n) __cmpxchg((ptr), (o), (n), RELAXED_MB)
#define cmpxchg_acquire(ptr, o, n) __cmpxchg((ptr), (o), (n), ACQUIRE_MB)
#define cmpxchg_release(ptr, o, n) __cmpxchg((ptr), (o), (n), RELEASE_MB)
#define cmpxchg(ptr, o, n)	   __cmpxchg((ptr), (o), (n), STRONG_MB)
#define cmpxchg_lock(ptr, o, n)    __cmpxchg((ptr), (o), (n), LOCK_MB)

#define __cmpxchg64(ptr, o, n, mem_model) \
({ \
	BUILD_BUG_ON(sizeof(*(ptr)) != 8); \
	(u64) __cmpxchg((ptr), (o), (n), mem_model); \
})
#define cmpxchg64_relaxed(ptr, o, n) __cmpxchg64((ptr), (o), (n), RELAXED_MB)
#define cmpxchg64_acquire(ptr, o, n) __cmpxchg64((ptr), (o), (n), ACQUIRE_MB)
#define cmpxchg64_release(ptr, o, n) __cmpxchg64((ptr), (o), (n), RELEASE_MB)
#define cmpxchg64(ptr, o, n)	     __cmpxchg64((ptr), (o), (n), STRONG_MB)

#define cmpxchg_double(p1, p2, o1, o2, n1, n2) \
	__api_cmpxchg_double(p1, p2, o1, o2, n1, n2)

#define cmpxchg_local(ptr, o, n)	cmpxchg_local((ptr), (o), (n))
#define cmpxchg64_local(ptr, o, n)	cmpxchg64((ptr), (o), (n))

#define system_has_cmpxchg_double() 1
#endif	/* ASM_E2K_CMPXCHG_H */
