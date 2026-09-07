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
#include <asm/compiler.h>
#include <asm/errno.h>
#include <asm/page.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include <asm/mmu_context.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#endif

/* Keep a hole between user memory and privileged so that
 * protected mode descriptors can never ever reach the
 * privileged area. It was true before v7 instruction set */
#define USER_ADDR_MAX	(USER_HW_STACKS_BASE - UL(0x100000000))
#define user_addr_max()	USER_ADDR_MAX

extern int __verify_write(const void *addr, unsigned long size);
extern int __verify_read(const void *addr, unsigned long size);
static inline bool __range_ok(unsigned long addr, unsigned long size,
		unsigned long limit)
{
	u64 __addr = (u64)untagged_addr(addr);
	BUILD_BUG_ON(!__builtin_constant_p(TASK32_SIZE));

	if (__builtin_constant_p(size) && size <= TASK32_SIZE)
		return likely(__addr <= limit - size);
	/* Arbitrary sizes? Be careful about overflow */
	return likely(__addr + size >= size && __addr + size <= limit);
}

register u64 uaccess_max ASM_GREG(UACCESS_MAX_GREG);
#define MAX_U_BORDER		user_addr_max()
#define get_u_border()		uaccess_max
#define set_u_border(v)		(uaccess_max = (v))
#define set_ap_u_border(ap)	set_u_border(AP_PTR(ap) + AP_OBJ_SIZE(ap))
#define set_max_u_border()	set_u_border(MAX_U_BORDER)

#define __access_ok(addr, size) \
({ \
	__chk_user_ptr(addr); \
	likely(__range_ok((unsigned long) (addr), (size), get_u_border())); \
})

/*
 * WARN_ON_IN_IRQ() and access_ok() are copy/paste from x86
 */
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
static inline bool pagefault_disabled(void);
# define WARN_ON_IN_IRQ()	\
	WARN_ON_ONCE(!in_task() && !pagefault_disabled())
#else
# define WARN_ON_IN_IRQ()
#endif

#define access_ok(addr, size) \
({ \
	WARN_ON_IN_IRQ(); \
	likely(__access_ok((addr), (size))); \
})

#define __access_priv_ok(addr, size) \
({ \
	__chk_priv_ptr(addr); \
	likely((unsigned long)(addr) >= user_addr_max() &&\
	       __range_ok((unsigned long) (addr), (size), PAGE_OFFSET)); \
})

#define access_priv_ok(addr, size) \
({ \
	WARN_ON_IN_IRQ(); \
	likely(__access_priv_ok((addr), (size))); \
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
	/* \
	 * There are places in kernel which: \
	 *  - call pagefault_disable(); \
	 *  - call some user access function; \
	 *  - manually fault-in any missing pages. \
	 * This pattern works only if user access function touches \
	 * only the memory it was explicitly asked to, thus such \
	 * functions must not use semi-speculative loads.  To make \
	 * sure this is the case, we disable corresponding mode. \
	 */ \
	noinline notrace __must_check __no_semispec long __uaccess_##name( \
			__MAP_UFN_ARGS(x,__UFN_DECL,args)) \
	{ \
		e2k_madmr_t madmr = E2K_MADMR_EMPTY; \
		if (cpu_has(CPU_FEAT_MADM)) \
			madmr = read_MADMR_reg(); \
		long ret = __uaccess_##name##_body(__MAP_UFN_ARGS(x,__UFN_ARGS,args)); \
		if (unlikely(madmr.mode_ld)) \
			__E2K_WAIT(_ld_c); \
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
		long ret; \
		\
		VM_BUG_ON((unsigned long) &__uaccess_##name < (unsigned long) __uaccess_start || \
			  (unsigned long) &__uaccess_##name >= (unsigned long) __uaccess_end); \
		uaccess_enable(); \
		ret = __uaccess_##name(__MAP_UFN_ARGS(x, __UFN_ARGS, args)); \
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
		unsigned long trap_ip = get_trap_ip(regs);
		unsigned long return_ip = get_return_ip(regs);

		return trap_ip >= (unsigned long) __uaccess_start &&
				trap_ip < (unsigned long) __uaccess_end ||
				search_exception_tables(return_ip);
	}

	return false;
}

extern bool handle_uaccess_trap(struct pt_regs *regs, bool skip_get_user);


extern int __noreturn __put_kernel_bad(void);

#define __put_kernel_nofault(dst, src, type, err_label) \
do { \
	u64 __x = (u64)(*(type *)(src)); \
	int __ret_pk; \
 \
	switch (sizeof(type)) { \
	case 1: \
		__ret_pk = PUT_KERNEL_ASM(__x, (type *)(src), b); \
		break; \
	case 2: \
		__ret_pk = PUT_KERNEL_ASM(__x, (type *)(src), h); \
		break; \
	case 4: \
		__ret_pk = PUT_KERNEL_ASM(__x, (type *)(src), w); \
		break; \
	case 8: \
		__ret_pk = PUT_KERNEL_ASM(__x, (type *)(src), d); \
		break; \
	default: \
		__ret_pk = -EFAULT; __put_kernel_bad(); break; \
	} \
 \
	if (unlikely(__ret_pk)) \
		goto err_label; \
} while (0)


extern int __noreturn __get_kernel_bad(void);

#define __get_kernel_nofault(dst, src, type, err_label) \
do { \
	int __ret_gk; \
 \
	switch (sizeof(type)) { \
	case 1: { \
		u8 __x; \
		GET_KERNEL_ASM(__x, (type *)(src), __ret_gk, b); \
		*((type *)(dst)) = (type)__x; \
		break; \
	} \
	case 2: { \
		u16 __x; \
		GET_KERNEL_ASM(__x, (type *)(src), __ret_gk, h); \
		*((type *)(dst)) = (type)__x; \
		break; \
	} \
	case 4: { \
		u32 __x; \
		GET_KERNEL_ASM(__x, (type *)(src), __ret_gk, w); \
		*((type *)(dst)) = (type)__x; \
		break; \
	} \
	case 8: { \
		u64 __x; \
		GET_KERNEL_ASM(__x, (type *)(src), __ret_gk, d); \
		*((type *)(dst)) = (type)__x; \
		break; \
	} \
	default: \
		__ret_gk = -EFAULT; __get_kernel_bad(); break; \
	} \
 \
	if (unlikely(__ret_gk)) \
		goto err_label; \
} while (0)

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
	int __ret_gu;	\
	uaccess_enable(); \
	__ret_gu = __get_user_switched_pt((x), ___gu_ptr); \
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
	(int) builtin_expect_wrapper(__ret_gu, 0); \
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
	(int) builtin_expect_wrapper(__ret_gu, 0); \
})

#define get_user_tagged_8(val, tag, ptr) \
({ \
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "pointer to tagged dword is not aligned"); \
	might_fault(); \
	!access_ok(__gu_ptr, 8) ? ((val) = (typeof(val)) 0, -EFAULT) : \
		   __get_user_tagged_8((val), (tag), __gu_ptr); \
})

#define __get_user_tagged_16(x, tag, ptr) \
({ \
	e2k_qreg_t ___x_gu; \
	int ___ret_gu; \
	const __typeof__(*(ptr)) __user *___gu_ptr = (ptr); \
	__chk_user_ptr(ptr); \
	GET_USER_VAL_AND_TAGQ(___x_gu.lo, ___x_gu.hi, (tag), ___gu_ptr, ___ret_gu, 8ul); \
	(x) = ___x_gu; \
	(int) builtin_expect_wrapper(___ret_gu, 0); \
})

#define get_user_tagged_16(x, tag, ptr) \
({ \
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr); \
	int __ret_gu; \
	might_fault(); \
	if (access_ok(__gu_ptr, 16)) { \
		__ret_gu = __get_user_tagged_16((x), (tag), __gu_ptr); \
	} else { \
		__ret_gu = -EFAULT; \
		(x) = (e2k_qreg_t) { .lo = 0, .hi = 0 }; \
		(tag) = (typeof(tag)) 0; \
	} \
	(int) builtin_expect_wrapper(__ret_gu, 0); \
})


		/**
		 * 		put user
		 */

extern int __put_user_bad(void) __attribute__((noreturn));

/*
 * __put_user() but caller must manually switch to user page tables.
 * Useful in protected fast syscalls since we can't access user space
 * directly (PTE.int_pr prohibits that) but page tables are from user.
 *
 * Returns -EFAULT on unhandled page fault and 0 otherwise.
 */
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
	(int) builtin_expect_wrapper(__ret_pu, 0); \
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

#define __put_user_tagged_16(x, tag, ptr) \
({ \
	e2k_qreg_t __x_pu = (x); \
	int __ret_pu; \
	__typeof__(*(ptr)) __user *____pu_ptr = (ptr); \
	__typeof__(tag) ___pu_tag = (tag); \
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ____pu_ptr, 16), \
			"unaligned put_user_tagged_16() parameter")) { \
		__ret_pu = -EFAULT; \
	} else { \
		PUT_USER_VAL_AND_TAGQ(__x_pu.lo, __x_pu.hi, ___pu_tag, \
				      ____pu_ptr, __ret_pu, 8ul); \
	} \
	(int) builtin_expect_wrapper(__ret_pu, 0); \
})

#define put_user_tagged_16(x, tag, ptr) \
({ \
	__typeof__(*(ptr)) __user *__pu_ptr = (ptr); \
	might_fault(); \
	!access_ok(__pu_ptr, sizeof(*__pu_ptr)) ? -EFAULT \
		: __put_user_tagged_16((x), (tag), __pu_ptr); \
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

static __always_inline unsigned long __must_check
copy_in_user(void __user *to, const void __user *from, unsigned long n)
{
	might_fault();
	if (access_ok(to, n) && access_ok(from, n))
		n = raw_copy_in_user(to, from, n);
	return n;
}





extern __must_check unsigned long raw_copy_in_user_with_tags(volatile void __user *to,
		const volatile void __user *from, unsigned long n);

static inline __must_check
unsigned long copy_in_user_tagged(volatile void __user *to, const volatile void __user *from,
				     unsigned long n)
{
	if (likely(access_ok(from, n) && access_ok(to, n)))
		n = raw_copy_in_user_with_tags(to, from, n);

	return n;
}




extern __must_check unsigned long raw_copy_to_user_with_tags(volatile void __user *to,
		const volatile void *from, unsigned long n);

static inline __must_check
unsigned long copy_to_user_tagged(volatile void __user *to, const volatile void *from,
				     unsigned long n)
{
	if (access_ok(to, n))
		n = raw_copy_to_user_with_tags(to, from, n);

	return n;
}




extern __must_check unsigned long raw_copy_from_user_with_tags(volatile void *to,
		const volatile void __user *from, unsigned long n);

static inline __must_check
unsigned long copy_from_user_tagged(volatile void *to, const volatile void __user *from,
				       unsigned long n)
{
	if (access_ok(from, n))
		n = raw_copy_from_user_with_tags(to, from, n);

	return n;
}




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
		unsigned long n, unsigned long tag, unsigned long dw, ldst_rec_op_t strd_opcode);

/* Filling aligned user pointer 'to' with 'n' bytes of 'dw' double words: */
static inline __must_check unsigned long
fill_user_with_tags(void __user *to, unsigned long n, unsigned long tag, unsigned long dw)
{
	ldst_rec_op_t opc = (ldst_rec_op_t) {
		.fmt = LDST_QWORD_FMT,
		.mas = MAS_BYPASS_L1_CACHE,
		.prot = 1,
	};
	int ret = 0;

	if (!access_ok(to, n))
		return n;

	if (__builtin_constant_p(n) && IS_ALIGNED((unsigned long) to, 16) && n <= 64 &&
			!(n % 16)) {
		if (n >= 16)
			ret = ASM_USER_STRD_16(to, dw, tag, AW(opc));
		if (n >= 32)
			ret |= ASM_USER_STRD_16(to, dw, tag, AW(opc) | 16);
		if (n >= 48)
			ret |= ASM_USER_STRD_16(to, dw, tag, AW(opc) | 32);
		if (n == 64)
			ret |= ASM_USER_STRD_16(to, dw, tag, AW(opc) | 48);
		return ret ? n : 0;
	}

	return __fill_user_with_tags(to, n, tag, dw, opc);
}

static inline __must_check unsigned long
clear_user_with_tags(void __user *ptr, unsigned long length, unsigned long tag)
{
	return fill_user_with_tags(ptr, length, tag, 0);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is virtualized guest kernel */
#include <asm/kvm/guest/uaccess.h>
#else
/* native kernel with virtualization support */
/* native kernel without virtualization support */

/**
 * get_priv - load value (1, 2, 4 or 8 bytes) from __priv area
 * @x: where to save loaded value
 * @ptr: address
 */
#define	get_priv(x, ptr) \
({ \
	const __typeof__(*(ptr)) __priv *__ptr_gpu = (ptr); \
	int __ret_gpu;	\
	/* Allow page faults on user privileged area */ \
	unsigned long __ts_flag_gpu = set_ts_flag(TS_KERNEL_SYSCALL); \
	if (likely(access_priv_ok(__ptr_gpu, sizeof(*__ptr_gpu)))) { \
		__ret_gpu = __get_user(x, (const __typeof__(*(ptr)) __user __force *) __ptr_gpu); \
	} else { \
		(x) = (__typeof__(x)) 0; \
		__ret_gpu = -EFAULT; \
	} \
	clear_ts_flag(__ts_flag_gpu); \
	(int) builtin_expect_wrapper(__ret_gpu, 0); \
})

/* Same as get_priv() but skips switching to user page tables */
#define	get_priv_switched_pt(x, ptr, ti) \
({ \
	const __typeof__(*(ptr)) __priv *__ptr_gpu = (ptr); \
	int __ret_gpu;	\
	/* Allow page faults on user privileged area */ \
	unsigned long __ts_flag_gpu = set_ti_status_flag(ti, TS_KERNEL_SYSCALL); \
	if (likely(access_priv_ok(__ptr_gpu, sizeof(*__ptr_gpu)))) { \
		__ret_gpu = __get_user_switched_pt(x, \
				(const __typeof__(*(ptr)) __user __force *) __ptr_gpu); \
	} else { \
		(x) = (__typeof__(x)) 0; \
		__ret_gpu = -EFAULT; \
	} \
	clear_ti_status_flag(ti, __ts_flag_gpu); \
	(int) builtin_expect_wrapper(__ret_gpu, 0); \
})

#define	__get_priv_tagged_16_offset(x, tag, ptr, offset) \
({ \
	const __typeof__(*(ptr)) __priv *____ptr_gpu = (ptr); \
	e2k_qreg_t ___x_gu; \
	int ____ret_gpu; \
	unsigned long __ts_flag_gpu = set_ts_flag(TS_KERNEL_SYSCALL); \
	GET_USER_VAL_AND_TAGQ(___x_gu.lo, ___x_gu.hi, (tag), \
			(const __typeof__(*(ptr)) __user __force *) ____ptr_gpu, \
			____ret_gpu, (offset)); \
	clear_ts_flag(__ts_flag_gpu); \
	(x) = ___x_gu; \
	(int) builtin_expect_wrapper(____ret_gpu, 0); \
})

/**
 * get_priv_tagged_16_offset - read tagged qword from @ptr
 * @x: e2k_qword_t for saving loaded value to
 * @tag: u32 for saving loaded external tag to
 * @offset: offset to second half of qword
 *
 * Useful for working with %qr registers in procedure stack.
 */
#define	get_priv_tagged_16_offset(x, tag, ptr, offset) \
({ \
	const __typeof__(*(ptr)) __priv *__ptr_gpu = (ptr); \
	const __typeof__(offset) __offset_gpu = (offset); \
	int __ret_gpu;	\
	if (likely(access_priv_ok(__ptr_gpu, __offset_gpu + 8))) { \
		__ret_gpu = __get_priv_tagged_16_offset((x), (tag), __ptr_gpu, __offset_gpu); \
	} else { \
		__ret_gpu = -EFAULT; \
		(x) = (e2k_qreg_t) { .lo = 0, .hi = 0 }; \
		(tag) = (__typeof__(tag)) 0; \
	} \
	(int) builtin_expect_wrapper(__ret_gpu, 0); \
})

/**
 * put_priv - store value (1, 2, 4 or 8 bytes) to __priv area
 * @x: value to store
 * @ptr: address
 */
#define	put_priv(x, ptr) \
({ \
	__typeof__(*(ptr)) __priv *__ptr_ppu = (ptr); \
	__typeof__(x) __x_ppu = (x); \
	int __ret_ppu;	\
	unsigned long __ts_flag_ppu = set_ts_flag(TS_KERNEL_SYSCALL); \
	if (likely(access_priv_ok(__ptr_ppu, sizeof(*__ptr_ppu)))) { \
		__ret_ppu = __put_user(__x_ppu, \
				(__typeof__(*(ptr)) __user __force *) __ptr_ppu); \
	} else { \
		__ret_ppu = -EFAULT; \
	} \
	clear_ts_flag(__ts_flag_ppu); \
	(int) builtin_expect_wrapper(__ret_ppu, 0); \
})

/* Same as put_priv() but skips switching to user page tables */
#define	put_priv_switched_pt(x, ptr, ti) \
({ \
	__typeof__(*(ptr)) __priv *__ptr_ppu = (ptr); \
	__typeof__(x) __x_ppu = (x); \
	int __ret_ppu;	\
	unsigned long __ts_flag_ppu = set_ti_status_flag(ti, TS_KERNEL_SYSCALL); \
	if (likely(access_priv_ok(__ptr_ppu, sizeof(*__ptr_ppu)))) { \
		__ret_ppu = __put_user_switched_pt(__x_ppu, \
				(__typeof__(*(ptr)) __user __force *) __ptr_ppu); \
	} else { \
		__ret_ppu = -EFAULT; \
	} \
	clear_ti_status_flag(ti, __ts_flag_ppu); \
	(int) builtin_expect_wrapper(__ret_ppu, 0); \
})

static __always_inline __must_check int
raw_put_priv_tagged_8(u64 x, u32 tag, void __priv *ptr)
{
	int ret;

	if (likely(access_priv_ok(ptr, 8))) {
		unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		PUT_USER_VAL_AND_TAGD(x, tag, (void __user __force *) ptr, ret);
		clear_ts_flag(ts_flag);
	} else {
		ret = -EFAULT;
	}

	return (int) builtin_expect_wrapper(ret, 0);
}

/**
 * put_priv_tagged_8 - store tagged dword to __priv area
 * @x: value to store
 * @tag: external tag to store
 * @ptr: address
 */
#define	put_priv_tagged_8(x, tag, ptr) \
({ \
	__typeof__(*(ptr)) __priv *__ptr_ppu = (ptr); \
	typeof(x) __x_ppu = (x); \
	typeof(tag) __tag_ppu = (tag); \
	BUILD_BUG_ON_MSG(__alignof(*(ptr)) != 8, "tagged pointer is not aligned"); \
	WARN_ONCE(!IS_ALIGNED((unsigned long) __ptr_ppu, 8), \
			"unaligned put_priv_tagged_8() parameter") ? \
		-EFAULT : \
		raw_put_priv_tagged_8(__x_ppu, __tag_ppu, __ptr_ppu); \
})

static __always_inline __must_check int
raw_put_priv_tagged_16_offset(e2k_qreg_t x, u32 tag, void __priv *ptr, size_t offset)
{
	int ret;

	if (likely(access_priv_ok(ptr, offset + 8))) {
		unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		PUT_USER_VAL_AND_TAGQ(x.lo, x.hi, tag, \
				(__typeof__(*(ptr)) __user __force *)  ptr, ret, offset);
		clear_ts_flag(ts_flag);
	} else {
		ret = -EFAULT;
	}

	return (int) builtin_expect_wrapper(ret, 0);
}

/**
 * put_priv_tagged_16_offset - save tagged qword to @ptr
 * @x: e2k_qword_t value to save
 * @tag: u32 tag for saving
 * @offset: offset to second half of qword
 *
 * Useful for working with %qr registers in procedure stack.
 */
#define	put_priv_tagged_16_offset(x, tag, ptr, offset) \
({ \
	__typeof__(*(ptr)) __priv *__ptr_ppu = (ptr); \
	typeof(x) __x_ppu = (x); \
	typeof(tag) __tag_ppu = (tag); \
	typeof(offset) __offset_ppu = (offset); \
	WARN_ONCE(!IS_ALIGNED((unsigned long) __ptr_ppu, 16), \
			"unaligned put_priv_tagged_16_offset() parameter") ? \
		-EFAULT : \
		raw_put_priv_tagged_16_offset(__x_ppu, __tag_ppu, __ptr_ppu, __offset_ppu); \
})

/**
 * copy_to_priv - untagged copy to __priv area
 * @to: __priv destination
 * @from: kernel source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_to_priv(void __priv *to, const void *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(to, n)))
		return n;

	/* Allow page faults on user privileged area */
	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_to_user((void __force __user *) to, from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_from_priv - untagged copy from __priv area
 * @to: kernel destination
 * @from: __priv source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_from_priv(void *to, const void __priv *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(from, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_from_user(to, (const void __force __user *) from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_in_priv - untagged copy in __priv area
 * @to: __priv destination
 * @from: __priv source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_in_priv(void __priv *to, const void __priv *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(from, n) || !access_priv_ok(to, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_in_user((void __force __user *) to,
			(const void __force __user *) from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_in_priv_tagged - tagged copy in __priv area
 * @to: __priv destination
 * @from: __priv source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_in_priv_tagged(volatile void __priv *to, const volatile void __priv *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(from, n) || !access_priv_ok(to, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_in_user_with_tags((volatile void __force __user *) to,
			(const volatile void __force __user *) from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_to_priv_tagged - tagged copy to __priv area
 * @to: __priv destination
 * @from: kernel source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_to_priv_tagged(volatile void __priv *to, const volatile void *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(to, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_to_user_with_tags((volatile void __force __user *) to, from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_from_priv_tagged - tagged copy from __priv area
 * @to: kernel destination
 * @from: __priv source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_from_priv_tagged(volatile void *to, const volatile void __priv *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(from, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_from_user_with_tags(to, (const void __force __user *) from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_priv_to_user_tagged - tagged copy from __priv area to __user area
 * @to: __user destination
 * @from: __priv source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_priv_to_user_tagged(volatile void __user *to,
			 const volatile void __priv *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(from, n) || !access_ok(to, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_in_user_with_tags(to, (const volatile void __force __user *) from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * copy_user_to_priv_tagged - tagged copy from __user area to __priv area
 * @to: __priv destination
 * @from: __user source
 * @n: length to copy
 */
static inline __must_check unsigned long
copy_user_to_priv_tagged(void __priv *to, const void __user *from, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(to, n) || !access_ok(from, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = raw_copy_in_user_with_tags((void __force __user *) to, from, n);
	clear_ts_flag(ts_flag);
	return left;
}

/**
 * clear_priv - clearing __priv area
 * @to: __priv destination
 * @n: length to clear
 */
static inline __must_check unsigned long
clear_priv(void __priv *to, unsigned long n)
{
	unsigned long left, ts_flag;

	if (unlikely(!access_priv_ok(to, n)))
		return n;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	left = __clear_user((void __force __user *) to, n);
	clear_ts_flag(ts_flag);
	return left;
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#ifdef CONFIG_PROTECTED_MODE

static __always_inline e2k_ap_t
new_ap_no_check(u64 base, u64 size, u64 ind, u64 rw)
{
	e2k_ap_t ap;
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		if (!size) {
			/* special case of v7 zero length AP */
			size = 1;
			ind = 0;
			rw = 0;
		}
		ap = (e2k_ap_t){.qword = NEW_V7_CPU_REG(base, ind, size)};
		ap.rw_v7 = rw;
		ap.itag_v7 = ITAG_AP;
	} else {
		ap = (e2k_ap_t) {.Base	= base, .Size	= size, .Curptr	= ind};
		ap.rw_v6 = rw;
		ap.itag_v6 = E2K_AP_ITAG;
	}
	return ap;
}

static __always_inline e2k_ap_t
new_ap(u64 base, u64 size, u64 ind, u64 rw)
{
	if (likely(size)) {
		if (unlikely(!access_ok((void __user __force *)base, size))) {
			base = 0;
			size = 0;
			ind = 0;
			rw = 0;
		}
	}
	return new_ap_no_check(base, size, ind, rw);
}

#define MAKE_FAKE_AP(base)		new_ap_no_check((unsigned long)(base), 0, 0, 0)
#define AP_NULL(ap, tag)		(!tag && !LO(ap))
#define MAKE_AP_RW(base, len, ind, rw)	new_ap((unsigned long)(base), (u64)(len), ind, rw)
#define MAKE_AP(base, len)		MAKE_AP_RW((base), (len), 0, RW_ENABLE)
#define MAKE_AP_IND(base, len, ind)	MAKE_AP_RW((base), (len), (ind), RW_ENABLE)

#define MAKE_TAGGED_AP_RW(ap, tag, base, len, ind, rw)		\
{								\
	ap = new_ap((u64)(base), (u64)(len), (ind), (rw));	\
	tag = ETAGAPQ;						\
}
#define MAKE_TAGGED_AP(ap, tag, base, len, ind) \
			MAKE_TAGGED_AP_RW(ap, tag, base, len, 0, RW_ENABLE)


static inline __must_check int PUT_USER_AP(e2k_ptr_t __user *ptr, u64 base,
	u64 len, u64 off, u64 rw)
{
	e2k_ap_t tmp;
	u32 tag;

	if (!IS_ALIGNED((unsigned long) ptr, sizeof(e2k_ptr_t)))
		return -EFAULT;

	if (base == 0) {
		tmp = MAKE_FAKE_AP(0);
		tag = ETAGNPQ;
	} else {
		tmp = MAKE_AP_RW(base, len, off, rw);
		tag = ETAGAPQ;
	}

	return put_user_tagged_16(tmp.qword, tag, ptr);
}


static inline __must_check int PUT_USER_PL(e2k_pl_t __user *plp, u64 entry, u32 cui)
{
	e2k_pl_t tmp = MAKE_PL(entry, cui);
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		if (!IS_ALIGNED((unsigned long) plp, sizeof(e2k_pl_t))) {
			return -EFAULT;
		}
		return put_user_tagged_16(tmp.qword, ETAGPL, plp);
	}
	/* This is v1..v5 architecture: */
	if (!IS_ALIGNED((unsigned long) plp, sizeof(u64))) {
		return -EFAULT;
	}
	/* In v3..v5 hiher half of the PL structure is just empty */
	int ret = put_user(0UL, &plp->hi);
	if (ret)
		return ret;
	return put_user_tagged_8(LO(tmp), E2K_PL_ETAG, &plp->lo);
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
	copied = native_fast_tagged_memory_copy(dst, (const void __force *)src, len,
				strd_opcode, ldrd_opcode, prefetch);
	RESTORE_USR_PFAULT(false);

	return copied;
}

static inline size_t fast_tagged_memory_copy_from_priv(volatile void *dst,
						       const volatile void __priv *src, size_t len,
						       int prefetch)
{
	size_t copied;
	ldst_rec_op_t strd_opcode = ldst_rec_qword();
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) {
		.fmt = LDST_QWORD_FMT,
		.mas = MAS_FILL_OPERATION(CACHE_BYPASS_L1, 0),
		.prot = 1,
	};

	unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	SET_USR_PFAULT("$recovery_memcpy_fault", false);
	copied = native_fast_tagged_memory_copy((void __force *)dst, (const void __force *)src, len,
						 strd_opcode, ldrd_opcode, prefetch);
	RESTORE_USR_PFAULT(false);

	clear_ts_flag(ts_flag);

	return copied;
}

static inline size_t fast_memory_copy_from_priv(void *dst, const void __priv *src, size_t len,
						       int prefetch)
{
	size_t copied;
	ldst_rec_op_t strd_opcode = ldst_rec_qword();
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) {
		.fmt = LDST_QWORD_FMT,
		.mas = MAS_FILL_OPERATION(CACHE_BYPASS_L1, 0),
		.prot = 1,
	};

	unsigned long ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	SET_USR_PFAULT("$recovery_memcpy_fault", false);
	copied = native_fast_tagged_memory_copy(dst, (const void __force *)src, len,
						 strd_opcode, ldrd_opcode, prefetch);
	RESTORE_USR_PFAULT(false);

	clear_ts_flag(ts_flag);

	return copied;
}
#endif /* _E2K_UACCESS_H_ */
