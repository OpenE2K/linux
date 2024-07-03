/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_UACCESS_H_
#define _E2K_UACCESS_H_

/*
 * User space memory access functions
 * asm/uaccess.h
 */
#include <linux/extable.h>
#include <linux/thread_info.h>

#include <asm/alternative.h>
#include <asm/errno.h>
#include <asm/page.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include <asm/mmu_context.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#endif

#undef	DEBUG_UACCESS_MODE
#undef	DebugUA
#define	DEBUG_UACCESS_MODE	0
#define	DebugUA			if (DEBUG_UACCESS_MODE) printk


/*
 * The fs value determines whether argument validity checking should be
 * performed or not.  If get_fs() == USER_DS, checking is performed, with
 * get_fs() == KERNEL_DS, checking is bypassed.
 *
 * For historical reasons, these macros are grossly misnamed.
 */

#define MAKE_MM_SEG(s)	((mm_segment_t) { (s) })

/* Even kernel should not access page tables with get_user()/put_user() */
#define KERNEL_DS	MAKE_MM_SEG(KERNEL_VPTB_BASE_ADDR)

/* Keep a hole between user memory and privileged so that
 * protected mode descriptors can never ever reach the
 * privileged area. */
#define USER_ADDR_MAX	(USER_HW_STACKS_BASE - UL(0x100000000))
#define USER_DS		MAKE_MM_SEG(USER_ADDR_MAX)

/*
 * Sometimes kernel wants to access hardware stacks,
 * in which case we can use this limit.
 *
 * IMPORTANT: in this case kernel must check that it accesses
 * only the stacks of the current thread. Writing another
 * thread's hardware stacks shall not be possible.
 */
#define K_USER_DS	MAKE_MM_SEG(PAGE_OFFSET)

#define get_ds()	(KERNEL_DS)
#define get_fs()	(current_thread_info()->addr_limit)
#define set_fs(x)	(current_thread_info()->addr_limit = (x))

#define segment_eq(a,b)	((a).seg == (b).seg)

#define uaccess_kernel() (get_fs().seg == KERNEL_DS.seg)
#define user_addr_max() (current_thread_info()->addr_limit.seg)

extern int __verify_write(const void *addr, unsigned long size);
extern int __verify_read(const void *addr, unsigned long size);

static inline bool __range_ok(unsigned long addr, unsigned long size,
		unsigned long limit)
{
	BUILD_BUG_ON(!__builtin_constant_p(TASK32_SIZE));

	if (__builtin_constant_p(size) && size <= TASK32_SIZE)
		return likely(addr <= limit - size);

	/* Arbitrary sizes? Be careful about overflow */
	return likely(addr + size >= size && addr + size <= limit);
}

#define access_ok(addr, size) \
({ \
	__chk_user_ptr(addr); \
	likely(__range_ok((unsigned long) (addr), (size), \
			  user_addr_max())); \
})

struct exception_table_entry
{
	unsigned long insn;
	unsigned long fixup;
};



/*
 * Copy-paste from syscalls.h as we want to use the same trick for
 * user-accessing functions.
 *
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP_UFN_ARGS0(m,...)
#define __MAP_UFN_ARGS1(m,t,a,...) m(t,a)
#define __MAP_UFN_ARGS2(m,t,a,...) m(t,a), __MAP_UFN_ARGS1(m,__VA_ARGS__)
#define __MAP_UFN_ARGS3(m,t,a,...) m(t,a), __MAP_UFN_ARGS2(m,__VA_ARGS__)
#define __MAP_UFN_ARGS4(m,t,a,...) m(t,a), __MAP_UFN_ARGS3(m,__VA_ARGS__)
#define __MAP_UFN_ARGS5(m,t,a,...) m(t,a), __MAP_UFN_ARGS4(m,__VA_ARGS__)
#define __MAP_UFN_ARGS6(m,t,a,...) m(t,a), __MAP_UFN_ARGS5(m,__VA_ARGS__)
#define __MAP_UFN_ARGS7(m,t,a,...) m(t,a), __MAP_UFN_ARGS6(m,__VA_ARGS__)
#define __MAP_UFN_ARGS(n,...) __MAP_UFN_ARGS##n(__VA_ARGS__)

#define __UFN_DECL(t, a)	t a
#define __UFN_ARGS(t, a)	a


/*
 * The macros to work safely in kernel with user memory.
 *
 * First, define a function that will do an access with UACCESS_FN_DEFINE.
 * Then call this function using UACCESS_FN_CALL().  On an unhandled page
 * fault it will return -EFAULT (see return_efault() call site for details
 * on how this is implemented), otherwise the return value is preserved.
 * For example:
 *
 *   UACCESS_FN_DEFINE2(name, int, arg1, void *, arg2)
 *   {
 *       if (<some condition>)
 *           return -EINVAL;
 *       < access user memory >
 *       return 0;
 *   }
 *
 *   long ret = UACCESS_FN_CALL(addr, size, name, arg1, arg2);
 *   if (ret == -EFAULT) {
 *       < handle bad access >
 *   } else if (ret == -EINVAL) {
 *       < handle bad parameter >
 *   }
 *
 * If you have already called access_ok(), you can call
 * __UACCESS_FN_CALL() instead to skip boundaries checking:
 *
 *   if (!access_ok(addr, size))
 *       return -EFAULT;
 *
 *   long ret = __UACCESS_FN_CALL(name, arg1, arg2);
 *   if (ret == -EFAULT)
 *       return ret;
 *
 * IMPORTANT: all user accesses must be in UACCESS_FN_DEFINE
 * function and not in its callees.
 *
 * NOTE2: hardware stacks and CUT lie in a special privileged area
 * for which access_ok() returns 'false'.
 *
 * NOTE3: 'noinline' because we want the function to lie in another section.
 * 'notrace' to not worry about having 'mcount' call and faulting user access
 * in the same wide instruction. Also without 'notrace' script recordmcount.pl
 * would need to be updated to take into account '.uaccess_functions' section.
 */
#define UACCESS_FN_DEFINEx(STATIC_FN, EXPORT, x, name, args...) \
	static __always_inline long __uaccess_##name##_body( \
			__MAP_UFN_ARGS(x,__UFN_DECL,args)); \
	STATIC_FN __section(".uaccess_functions") \
	/* There are places in kernel which: \
	 *  - call pagefault_disable(); \
	 *  - call some user access function; \
	 *  - manually fault-in any missing pages. \
	 * This pattern works only if user access function touches \
	 * only the memory it was explicitly asked to, thus such \
	 * functions must not use half-speculative loads.  To make \
	 * sure this is the case, we disable corresponding mode. \
	 * \
	 * TODO bug 140465 - replace O1 with only needed options */ \
	__attribute__((optimize("O1"))) \
	noinline notrace __must_check long __uaccess_##name( \
			__MAP_UFN_ARGS(x,__UFN_DECL,args)) \
	{ \
		long ret = __uaccess_##name##_body(__MAP_UFN_ARGS(x,__UFN_ARGS,args)); \
		/* A user-access function will return -EFAULT if an unhandled \
		 * page fault happens, but compiler does not know about this. \
		 * So we always hide the returned value to make sure that \
		 * compiler does not assume it never equals -EFAULT. */ \
		OPTIMIZER_HIDE_VAR(ret); \
		return ret; \
	} \
	EXPORT \
	static __always_inline long __uaccess_##name##_body( \
			__MAP_UFN_ARGS(x,__UFN_DECL,args))

/* static version (usage in the same file).  This basically adds
 * 'static' storage class and integrates UACCESS_FN_DECLAREx() */
#define UACCESS_FN_DEFINE1(name, args...) \
		UACCESS_FN_DECLAREx(static, 1, name, args); \
		UACCESS_FN_DEFINEx(static, , 1, name, args)
#define UACCESS_FN_DEFINE2(name, args...) \
		UACCESS_FN_DECLAREx(static, 2, name, args); \
		UACCESS_FN_DEFINEx(static, , 2, name, args)
#define UACCESS_FN_DEFINE3(name, args...) \
		UACCESS_FN_DECLAREx(static, 3, name, args); \
		UACCESS_FN_DEFINEx(static, , 3, name, args)
#define UACCESS_FN_DEFINE4(name, args...) \
		UACCESS_FN_DECLAREx(static, 4, name, args); \
		UACCESS_FN_DEFINEx(static, , 4, name, args)
#define UACCESS_FN_DEFINE5(name, args...) \
		UACCESS_FN_DECLAREx(static, 5, name, args); \
		UACCESS_FN_DEFINEx(static, , 5, name, args)
#define UACCESS_FN_DEFINE6(name, args...) \
		UACCESS_FN_DECLAREx(static, 6, name, args); \
		UACCESS_FN_DEFINEx(static, , 6, name, args)
#define UACCESS_FN_DEFINE7(name, args...) \
		UACCESS_FN_DECLAREx(static, 7, name, args); \
		UACCESS_FN_DEFINEx(static, , 7, name, args)

/* *_GLOB_* version for defining not-static function */
#define UACCESS_GLOB_FN_DEFINE1(name, ...) \
		UACCESS_FN_DEFINEx(, , 1, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE2(name, ...) \
		UACCESS_FN_DEFINEx(, , 2, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE3(name, ...) \
		UACCESS_FN_DEFINEx(, , 3, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE4(name, ...) \
		UACCESS_FN_DEFINEx(, , 4, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE5(name, ...) \
		UACCESS_FN_DEFINEx(, , 5, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE6(name, ...) \
		UACCESS_FN_DEFINEx(, , 6, name, __VA_ARGS__)
#define UACCESS_GLOB_FN_DEFINE7(name, ...) \
		UACCESS_FN_DEFINEx(, , 7, name, __VA_ARGS__)

/* *_GLOBEXP_* version for defining not-static function with EXPORT_SYMBOL() */
#define UACCESS_GLOBEXP_FN_DEFINE1(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 1, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE2(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 2, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE3(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 3, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE4(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 4, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE5(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 5, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE6(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 6, name, __VA_ARGS__)
#define UACCESS_GLOBEXP_FN_DEFINE7(name, ...) \
		UACCESS_FN_DEFINEx(, EXPORT_SYMBOL(__uaccess_##name);, 7, name, __VA_ARGS__)

#define UACCESS_FN_DECLAREx(STATIC_FN, x, name, args...) \
	STATIC_FN long __must_check __uaccess_##name(__MAP_UFN_ARGS(x,__UFN_DECL,args)); \
	static __always_inline long __uaccess_##name##_switch_pt( \
			__MAP_UFN_ARGS(x,__UFN_DECL,args)) \
	{ \
		VM_BUG_ON((unsigned long) &__uaccess_##name < (unsigned long) __uaccess_start || \
			  (unsigned long) &__uaccess_##name >= (unsigned long) __uaccess_end); \
		uaccess_enable(); \
		long ret = __uaccess_##name(__MAP_UFN_ARGS(x,__UFN_ARGS,args)); \
		uaccess_disable(); \
		return ret; \
	}

#define UACCESS_FN_DECLARE1(name, ...) UACCESS_FN_DECLAREx(, 1, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE2(name, ...) UACCESS_FN_DECLAREx(, 2, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE3(name, ...) UACCESS_FN_DECLAREx(, 3, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE4(name, ...) UACCESS_FN_DECLAREx(, 4, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE5(name, ...) UACCESS_FN_DECLAREx(, 5, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE6(name, ...) UACCESS_FN_DECLAREx(, 6, name, __VA_ARGS__)
#define UACCESS_FN_DECLARE7(name, ...) UACCESS_FN_DECLAREx(, 7, name, __VA_ARGS__)

#define UACCESS_FN_CALL(addr, size, ...) \
({ \
	likely(access_ok((addr), (size))) ? __UACCESS_FN_CALL(__VA_ARGS__) : \
			(might_fault(), -EFAULT); \
})

/* This variant can be used only if you've
 * checked address with access_ok() already */
#define __UACCESS_FN_CALL(...) \
({ \
	might_fault(); \
	____UACCESS_FN_CALL(__VA_ARGS__); \
})

/* This is the same as __UACCESS_FN_CALL()
 * but for usage in atomic context */
#define ____UACCESS_FN_CALL(name, args...) \
({ \
	__uaccess_##name##_switch_pt(args); \
})

#define SET_USR_PFAULT(name, ua_enabled) \
	unsigned long _usr_pfault_jmp = current->thread.usr_pfault_jump; \
	if (!(ua_enabled)) \
		uaccess_enable(); \
	GET_LBL_ADDR(name, current->thread.usr_pfault_jump)

#define RESTORE_USR_PFAULT(ua_enabled) \
({ \
	unsigned long __pfault_result = current->thread.usr_pfault_jump; \
	if (!(ua_enabled)) \
		uaccess_disable(); \
	current->thread.usr_pfault_jump = _usr_pfault_jmp; \
	unlikely(!__pfault_result); \
})

static inline int from_uaccess_allowed_code(const struct pt_regs *regs)
{
	if (current->thread.usr_pfault_jump || user_mode(regs))
		return true;

	if (from_trap(regs)) {
		unsigned long ip = get_trap_ip(regs);

		return ip >= (unsigned long) __uaccess_start &&
				ip < (unsigned long) __uaccess_end ||
				search_exception_tables(ip);
	}

	return false;
}

extern bool handle_uaccess_trap(struct pt_regs *regs, bool exc_diag);

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 *
 * This gets kind of ugly. We want to return _two_ values in "get_user()"
 * and yet we don't want to do any pointers, because that is too much
 * of a performance impact. Thus we have a few rather ugly macros here,
 * and hide all the uglyness from the user.
 *
 * The "__xxx" versions of the user access functions are versions that
 * do not verify the address space, that must have been done previously
 * with a separate "access_ok()" call (this is used when we do multiple
 * accesses to the same area of user memory).
 */

#ifdef CONFIG_KVM_GUEST_KERNEL
# include <asm/kvm/guest/uaccess.h>
#else
# define GET_USER_VAL_AND_TAGW(...) \
do { \
	uaccess_enable(); \
	NATIVE_GET_USER_VAL_AND_TAGW(__VA_ARGS__); \
	uaccess_disable(); \
} while (0)
# define GET_USER_VAL_AND_TAGD(...) \
do { \
	uaccess_enable(); \
	NATIVE_GET_USER_VAL_AND_TAGD(__VA_ARGS__); \
	uaccess_disable(); \
} while (0)
# define GET_USER_VAL_AND_TAGQ(...) \
do { \
	uaccess_enable(); \
	NATIVE_GET_USER_VAL_AND_TAGQ(__VA_ARGS__); \
	uaccess_disable(); \
} while (0)
# define PUT_USER_VAL_AND_TAGD(...) \
do { \
	uaccess_enable(); \
	NATIVE_PUT_USER_VAL_AND_TAGD(__VA_ARGS__); \
	uaccess_disable(); \
} while (0)
# define PUT_USER_VAL_AND_TAGQ(...) \
do { \
	uaccess_enable(); \
	NATIVE_PUT_USER_VAL_AND_TAGQ(__VA_ARGS__); \
	uaccess_disable(); \
} while (0)
#endif

		/**
		 * 		get user
		 */

extern int __get_user_bad(void) __attribute__((noreturn));

/* __get_user() but caller must manually switch to user page tables.
 * Useful in protected fast syscalls since we can't access user space
 * directly (PTE.int_pr prohibits that) but page tables are from user. */
#define __get_user_switched_pt(x, ptr) \
({									\
	const __typeof__(*(ptr)) __user *__gusp_ptr = (ptr);		\
	ldst_rec_op_t __gu_opc = { .prot = 1 }; \
	int __ret_gusp;							\
	__chk_user_ptr(ptr);						\
	switch (sizeof(*__gusp_ptr)) {					\
	case 1: \
		__gu_opc.fmt = LDST_BYTE_FMT; \
		GET_USER_ASM(x, __gusp_ptr, __gu_opc.word, __ret_gusp, b); \
		break; \
	case 2: \
		__gu_opc.fmt = LDST_HALF_FMT; \
		GET_USER_ASM(x, __gusp_ptr, __gu_opc.word, __ret_gusp, h); \
		break; \
	case 4: \
		__gu_opc.fmt = LDST_WORD_FMT; \
		GET_USER_ASM(x, __gusp_ptr, __gu_opc.word, __ret_gusp, w); \
		break; \
	case 8: \
		__gu_opc.fmt = LDST_DWORD_FMT; \
		GET_USER_ASM(x, __gusp_ptr, __gu_opc.word, __ret_gusp, d); \
		break; \
	default:							\
		__ret_gusp = -EFAULT; __get_user_bad(); break;		\
	}								\
	(int) builtin_expect_wrapper(__ret_gusp, 0);			\
})

#define __get_user(x, ptr) \
({ \
	const __typeof__(*(ptr)) __user *___gu_ptr = (ptr); \
	uaccess_enable(); \
	int __ret_gu = __get_user_switched_pt((x), ___gu_ptr); \
	uaccess_disable(); \
	__ret_gu; \
})

#define get_user(x, ptr)						\
({									\
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
	might_fault();							\
	access_ok(__gu_ptr, sizeof(*__gu_ptr)) ?			\
		__get_user((x), __gu_ptr) :                             \
		((x) = (__typeof__(x)) 0, -EFAULT);                     \
})

#define __get_user_tagged_4(val, tag, ptr) \
({ \
	int __ret_gu; \
	const __typeof__(*(ptr)) __user *____gu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) < 4, "tagged pointer is not aligned"); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____gu_ptr, 4), \
			"unaligned get_user_tagged_4() parameter")) { \
		__ret_gu = -EFAULT; \
	} else { \
		GET_USER_VAL_AND_TAGW((val), (tag), ____gu_ptr, __ret_gu); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_gu, 0); \
})

#define get_user_tagged_4(val, tag, ptr) \
({ \
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) < 4, "tagged pointer is not aligned"); \
	might_fault(); \
	!access_ok(__gu_ptr, 4) ? ((val) = (typeof(val)) 0, -EFAULT) : \
		   __get_user_tagged_4((val), (tag), __gu_ptr); \
})

#define __get_user_tagged_8(val, tag, ptr) \
({ \
	int __ret_gu; \
	const __typeof__(*(ptr)) __user *____gu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "pointer to tagged dword is not aligned"); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____gu_ptr, 8), \
			"unaligned get_user_tagged_8() parameter")) { \
		__ret_gu = -EFAULT; \
	} else { \
		GET_USER_VAL_AND_TAGD((val), (tag), ____gu_ptr, __ret_gu); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_gu, 0); \
})

#define get_user_tagged_8(val, tag, ptr) \
({ \
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "pointer to tagged dword is not aligned"); \
	might_fault(); \
	!access_ok(__gu_ptr, 8) ? ((val) = (typeof(val)) 0, -EFAULT) : \
		   __get_user_tagged_8((val), (tag), __gu_ptr); \
})

#define __get_user_tagged_16(val_lo, val_hi, tag, ptr) \
({ \
	int __ret_gu; \
	const __typeof__(*(ptr)) __user *____gu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____gu_ptr, 16), \
			"unaligned get_user_tagged_16() parameter")) { \
		__ret_gu = -EFAULT; \
	} else { \
		GET_USER_VAL_AND_TAGQ((val_lo), (val_hi), (tag), \
				      ____gu_ptr, __ret_gu, 8ul); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_gu, 0); \
})

#define get_user_tagged_16(val_lo, val_hi, tag, ptr) \
({ \
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr); \
	might_fault(); \
	!access_ok(__gu_ptr, 16) \
		? ((val_lo) = (typeof(val_lo)) 0, (val_hi) = (typeof(val_hi)) 0, -EFAULT) \
		: __get_user_tagged_16((val_lo), (val_hi), (tag), __gu_ptr); \
})

/* Special version for accessing procedure stack directly in memory */
#define __get_user_tagged_16_offset(val_lo, val_hi, tag, ptr, offset) \
({ \
	int __ret_gu; \
	const __typeof__(*(ptr)) __user *____gu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____gu_ptr, 8), \
			"unaligned get_user_tagged_16() parameter")) { \
		__ret_gu = -EFAULT; \
	} else { \
		GET_USER_VAL_AND_TAGQ((val_lo), (val_hi), (tag), \
				      ____gu_ptr, __ret_gu, (offset)); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_gu, 0); \
})


		/**
		 * 		put user
		 */

extern int __put_user_bad(void) __attribute__((noreturn));

/* __put_user() but caller must manually switch to user page tables.
 * Useful in protected fast syscalls since we can't access user space
 * directly (PTE.int_pr prohibits that) but page tables are from user. */
#define __put_user_switched_pt(x, ptr) \
({									\
	__typeof__(*(ptr)) __user *__pusp_ptr = (ptr);			\
	__typeof__(*(ptr)) __pusp_val  = (x);				\
	ldst_rec_op_t __pu_opc = { .prot = 1 }; \
	int __ret_pusp;							\
	__chk_user_ptr(ptr);						\
	switch (sizeof(*__pusp_ptr)) {					\
	case 1: \
		__pu_opc.fmt = LDST_BYTE_FMT; \
		PUT_USER_ASM(__pusp_val, __pusp_ptr, __pu_opc.word, __ret_pusp, b); \
		break; \
	case 2: \
		__pu_opc.fmt = LDST_HALF_FMT; \
		PUT_USER_ASM(__pusp_val, __pusp_ptr, __pu_opc.word, __ret_pusp, h); \
		break; \
	case 4: \
		__pu_opc.fmt = LDST_WORD_FMT; \
		PUT_USER_ASM(__pusp_val, __pusp_ptr, __pu_opc.word, __ret_pusp, w); \
		break; \
	case 8: \
		__pu_opc.fmt = LDST_DWORD_FMT; \
		PUT_USER_ASM(__pusp_val, __pusp_ptr, __pu_opc.word, __ret_pusp, d); \
		break; \
	default:							\
		__ret_pusp = -EFAULT; __put_user_bad(); break;		\
	}								\
	(int) builtin_expect_wrapper(__ret_pusp, 0);			\
})

#define __put_user(x, ptr) \
({ \
	__typeof__(*(ptr)) __user *___pu_ptr = (ptr); \
	__typeof__(*(ptr)) ___pu_val = (x); \
	uaccess_enable(); \
	int __ret_pu = __put_user_switched_pt(___pu_val, ___pu_ptr); \
	uaccess_disable(); \
	__ret_pu; \
})

#define put_user(x, ptr)						\
({									\
	__typeof__(*(ptr)) __user *__pu_ptr = (ptr);			\
	might_fault();							\
	(access_ok(__pu_ptr, sizeof(*__pu_ptr))) ?			\
		__put_user((x), __pu_ptr) : -EFAULT;			\
})

#define __put_user_tagged_8(val, tag, ptr) \
({ \
	int __ret_pu; \
	__typeof__(*(ptr)) __user *____pu_ptr = (ptr); \
	__typeof__(val) ___pu_val = (val); \
	__typeof__(tag) ___pu_tag = (tag); \
	__chk_user_ptr(ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "tagged pointer is not aligned"); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____pu_ptr, 8), \
			"unaligned put_user_tagged_8() parameter")) { \
		__ret_pu = -EFAULT; \
	} else { \
		PUT_USER_VAL_AND_TAGD(___pu_val, ___pu_tag, ____pu_ptr, __ret_pu); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_pu, 0); \
})

#define put_user_tagged_8(val, tag, ptr) \
({ \
	__typeof__(*(ptr)) __user *__pu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "tagged pointer is not aligned"); \
	might_fault(); \
	!access_ok(__pu_ptr, sizeof(*__pu_ptr)) ? -EFAULT : \
			__put_user_tagged_8((val), (tag), __pu_ptr); \
})

#define __put_user_tagged_16(val_lo, val_hi, tag, ptr) \
({ \
	int __ret_pu; \
	__typeof__(*(ptr)) __user *____pu_ptr = (ptr); \
	__typeof__(val_lo) ___pu_val_lo = (val_lo); \
	__typeof__(val_hi) ___pu_val_hi = (val_hi); \
	__typeof__(tag) ___pu_tag = (tag); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____pu_ptr, 16), \
			"unaligned put_user_tagged_16() parameter")) { \
		__ret_pu = -EFAULT; \
	} else { \
		PUT_USER_VAL_AND_TAGQ(___pu_val_lo, ___pu_val_hi, ___pu_tag, \
				      ____pu_ptr, __ret_pu, 8ul); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_pu, 0); \
})

#define put_user_tagged_16(val_lo, val_hi, tag, ptr) \
({ \
	__typeof__(*(ptr)) __user *__pu_ptr = (ptr); \
	might_fault(); \
	!access_ok(__pu_ptr, sizeof(*__pu_ptr)) ? -EFAULT \
		: __put_user_tagged_16((val_lo), (val_hi), (tag), __pu_ptr); \
})

/* Special version for accessing procedure stack directly in memory */
#define __put_user_tagged_16_offset(val_lo, val_hi, tag, ptr, offset) \
({ \
	int __ret_pu; \
	__typeof__(*(ptr)) __user *____pu_ptr = (ptr); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____pu_ptr, 8), \
			"unaligned put_user_tagged_16() parameter")) { \
		__ret_pu = -EFAULT; \
	} else { \
		PUT_USER_VAL_AND_TAGQ((val_lo), (val_hi), (tag), \
				      ____pu_ptr, __ret_pu, (offset)); \
	} \
	/* See bug #113288: should switch to expect_with_probablity */ \
	(int) __builtin_expect(__ret_pu, 0); \
})

#define INLINE_COPY_FROM_USER
#define INLINE_COPY_TO_USER

UACCESS_FN_DECLARE4(copy_from_user_fn, void *, to, const void __user *, from,
		unsigned long, size, unsigned long *, left);
static inline __must_check unsigned long raw_copy_from_user(void *to,
		const void __user *from, unsigned long size)
{
	unsigned long left = size;

	if (__builtin_constant_p(size) &&
			(size == 1 || size == 2 || size == 4 || size == 8)) {
		if (unlikely(size == 1 && __get_user(*(u8 *) to, (const u8 __user *) from) ||
			     size == 2 && __get_user(*(u16 *) to, (const u16 __user *) from) ||
			     size == 4 && __get_user(*(u32 *) to, (const u32 __user *) from) ||
			     size == 8 && __get_user(*(u64 *) to, (const u64 __user *) from)))
			return size;
		return 0;
	}

	if (unlikely(__UACCESS_FN_CALL(copy_from_user_fn, to, from, size, &left)))
		return left;

	return 0;
}

UACCESS_FN_DECLARE4(copy_in_user_fn, void __user *, to, const void __user *, from,
		unsigned long, size, unsigned long *, left);
static inline __must_check unsigned long raw_copy_in_user(void __user *to,
		const void __user *from, unsigned long size)
{
	unsigned long left = size;

	if (unlikely(__UACCESS_FN_CALL(copy_in_user_fn, to, from, size, &left)))
		return left;

	return 0;
}

UACCESS_FN_DECLARE4(copy_to_user_fn, void __user *, to, const void *, from,
		unsigned long, size, unsigned long *, left);
static inline __must_check unsigned long raw_copy_to_user(void __user *to,
		const void *from, unsigned long size)
{
	unsigned long left = size;

	if (__builtin_constant_p(size) &&
			(size == 1 || size == 2 || size == 4 || size == 8)) {
		if (unlikely(size == 1 && __put_user(*(const u8 *) from, (u8 __user *) to) ||
			     size == 2 && __put_user(*(const u16 *) from, (u16 __user *) to) ||
			     size == 4 && __put_user(*(const u32 *) from, (u32 __user *) to) ||
			     size == 8 && __put_user(*(const u64 *) from, (u64 __user *) to)))
			return size;
		return 0;
	}

	if (unlikely(__UACCESS_FN_CALL(copy_to_user_fn, to, from, size, &left)))
		return left;

	return 0;
}

extern __must_check unsigned long __copy_in_user_with_tags(void __user *to,
		const void __user *from, unsigned long n);
static inline __must_check
unsigned long copy_in_user_with_tags(void __user *to, const void __user *from,
				     unsigned long n)
{
	if (likely(access_ok(from, n) && access_ok(to, n)))
		n = __copy_in_user_with_tags(to, from, n);

	return n;
}

extern __must_check unsigned long __copy_to_user_with_tags(void __user *to,
		const void *from, unsigned long n);
static inline __must_check
unsigned long copy_to_user_with_tags(void __user *to, const void *from,
				     unsigned long n)
{
	if (access_ok(to, n))
		n = __copy_to_user_with_tags(to, from, n);

	return n;
}

extern __must_check unsigned long __copy_from_user_with_tags(void *to,
		const void __user *from, unsigned long n);
static inline __must_check
unsigned long copy_from_user_with_tags(void *to, const void __user *from,
				       unsigned long n)
{
	if (access_ok(from, n))
		n = __copy_from_user_with_tags(to, from, n);

	return n;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is virtualized guest kernel */
#include <asm/kvm/guest/uaccess.h>
#elif	defined(CONFIG_VIRTUALIZATION) || !defined(CONFIG_VIRTUALIZATION)
/* native kernel with virtualization support */
/* native kernel without virtualization support */

#define	__get_priv_user(x, ptr)		__get_user(x, ptr)
#define __put_priv_user(x, ptr)		__put_user(x, ptr)
#define	get_priv_user(x, ptr)		get_user(x, ptr)
#define	put_priv_user(x, ptr)		put_user(x, ptr)

#define __copy_to_priv_user		__copy_to_user
#define __copy_from_priv_user		__copy_from_user
#define __copy_to_priv_user_with_tags	__copy_to_user_with_tags
#define __copy_from_priv_user_with_tags	__copy_from_user_with_tags

static inline
unsigned long copy_to_priv_user_with_tags(void __user *to, const void *from,
					  unsigned long n)
{
	return copy_to_user_with_tags(to, from, n);
}

static inline
unsigned long copy_from_priv_user_with_tags(void *to, const void __user *from,
					    unsigned long n)
{
	return copy_from_user_with_tags(to, from, n);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#define strlen_user(str) strnlen_user(str, ~0UL >> 1)
__must_check long strnlen_user(const char __user *str, long count) __pure;

__must_check long strncpy_from_user(char *dst, const char __user *src, long count);


__must_check unsigned long __fill_user(void __user *mem,
		unsigned long len, const u8 b);

static inline __must_check unsigned long
fill_user(void __user *to, unsigned long n, const u8 b)
{
	if (!access_ok(to, n))
		return n;

	return __fill_user(to, n, b);
}

#define __clear_user(mem, len) __fill_user(mem, len, 0)
#define clear_user(to, n) fill_user(to, n, 0)


__must_check unsigned long __fill_user_with_tags(void __user *dst,
		unsigned long n, unsigned long tag, unsigned long dw);

/* Filling aligned user pointer 'to' with 'n' bytes of 'dw' double words: */
static inline __must_check unsigned long
fill_user_with_tags(void __user *to, unsigned long n, unsigned long tag, unsigned long dw)
{
	if (!access_ok(to, n))
		return n;

	return __fill_user_with_tags(to, n, tag, dw);
}

static inline __must_check unsigned long
clear_user_with_tags(void __user *ptr, unsigned long length, unsigned long tag)
{
	return fill_user_with_tags(ptr, length, tag, 0);
}

#ifdef CONFIG_PROTECTED_MODE

static inline __must_check int PUT_USER_AP(e2k_ptr_t __user *ptr, u64 base,
        u64 len, u64 off, u64 rw)
{
	u64 tmp_lo, tmp_hi;
	u32 tag;

	if (!IS_ALIGNED((unsigned long) ptr, sizeof(e2k_ptr_t)))
		return -EFAULT;

	if (base == 0) {
		tmp_lo = 0;
		tmp_hi = 0;
		tag = ETAGNVQ;
	} else {
		tmp_lo = MAKE_AP_LO(base, len, off, rw);
		tmp_hi = MAKE_AP_HI(base, len, off, rw);
		tag = ETAGAPQ;
	}

	return put_user_tagged_16(tmp_lo, tmp_hi, tag, ptr);
}

static inline __must_check int PUT_USER_PL_V3(e2k_pl_lo_t __user *plp, u64 entry)
{
	e2k_pl_lo_t tmp = MAKE_PL_V3(entry).lo;

	if (!IS_ALIGNED((unsigned long) plp, sizeof(e2k_pl_lo_t)))
		return -EFAULT;

	return put_user_tagged_8(AW(tmp), E2K_PL_ETAG, plp);
}

static inline __must_check int PUT_USER_PL_V6(e2k_pl_t __user *plp, u64 entry, u32 cui)
{
	e2k_pl_t tmp = MAKE_PL_V6(entry, cui);

	if (!IS_ALIGNED((unsigned long) plp, sizeof(e2k_pl_t)))
		return -EFAULT;

	return put_user_tagged_16(AW(tmp.lo), AW(tmp.hi), ETAGPLQ, plp);
}

static inline __must_check int PUT_USER_PL(e2k_pl_t __user *plp, u64 entry, u32 cui)
{
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		return PUT_USER_PL_V6(plp, entry, cui);
	} else {
		int ret = put_user(0UL, &AW(plp->hi));
		if (ret)
			return ret;
		return PUT_USER_PL_V3(&plp->lo, entry);
	}
}

#endif /* CONFIG_PROTECTED_MODE */

static inline __must_check size_t native_fast_tagged_memory_copy_to_user(
		void __user *dst, const void *src, size_t len,
		const struct pt_regs *regs, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch)
{
	size_t copied;

	/* native kernel does not support any guests */
	SET_USR_PFAULT("$recovery_memcpy_fault", false);
	copied = native_fast_tagged_memory_copy((void __force *) dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
	RESTORE_USR_PFAULT(false);

	return copied;
}

static inline __must_check size_t native_fast_tagged_memory_copy_from_user(
		void *dst, const void __user *src, size_t len,
		const struct pt_regs *regs, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch)
{
	size_t copied;

	SET_USR_PFAULT("$recovery_memcpy_fault", false);
	/* native kernel does not support any guests */
	copied = native_fast_tagged_memory_copy(dst, (const void *)src, len,
				strd_opcode, ldrd_opcode, prefetch);
	RESTORE_USR_PFAULT(false);

	return copied;
}

#ifndef CONFIG_COMPAT
/* NB> Function copy_in_user() is defined in include/linux/uaccess.h for compat mode only.
 *     The function body copied over here not to block non-compat configs.
 */
static __always_inline unsigned long __must_check
copy_in_user(void __user *to, const void __user *from, unsigned long n)
{
	might_fault();
	if (access_ok(to, n) && access_ok(from, n))
		n = raw_copy_in_user(to, from, n);
	return n;
}
#endif

#endif /* _E2K_UACCESS_H_ */
