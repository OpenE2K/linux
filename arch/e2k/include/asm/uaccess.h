#ifndef _E2K_UACCESS_H_
#define _E2K_UACCESS_H_

/*
 * User space memory access functions
 * asm/uaccess.h
 */
#include <linux/thread_info.h>

#include <asm/alternative.h>
#include <asm/errno.h>
#include <asm/page.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#endif

#undef	DEBUG_UACCESS_MODE
#undef	DEBUG_UACCESS_FAULT
#undef	DebugUA
#undef	DebugUAF
#define	DEBUG_UACCESS_MODE	0
#define	DEBUG_UACCESS_FAULT	0
#define	DebugUA			\
	if (DEBUG_UACCESS_MODE) printk
#if DEBUG_UACCESS_MODE || DEBUG_UACCESS_FAULT
# define DebugUAF		printk
#else
# define DebugUAF(...)
#endif



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

#define USER_ADDR_MAX	USER_HW_STACKS_BASE
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
	likely(__range_ok((unsigned long __force) (addr), (size), \
			  user_addr_max())); \
})

struct exception_table_entry
{
	unsigned long insn;
	unsigned long fixup;
};


/*
 * The macros to work safely in kernel with user memory:
 *
 *	TRY_USR_PFAULT {
 *		... // "try" code which accesses user memory
 *	} CATCH_USR_PFAULT {
 *		... // "catch" code after page fault (bad user's address)  
 *	} END_USR_PFAULT
 *
 * NOTE1: these macros can be used inside of "catch" code,
 *	  but can *not* be used inside of "try" code
 * NOTE2: the compiler believes that after global label we CAN'T use
 *        local context so __result__ must be initialized after the label.
 * NOTE3: any variable that is used in both "if" and "else" blocks must
 *        be marked with "volatile" keyword. Caveat: mark the variable
 *	  itself and not the memory it is pointing to, i.e:
 *		int *volatile ptr <=== RIGHT
 *		volatile int *ptr <=== WRONG
 */                   

#define TRY_USR_PFAULT \
	might_fault(); \
	__TRY_USR_PFAULT

#pragma unknown_control_flow(set_usr_pfault_jump)
static __always_inline void set_usr_pfault_jump(void)
{
	SAVE_CURRENT_ADDR(&current_thread_info()->usr_pfault_jump);
}

#define __TRY_USR_PFAULT \
	unsigned long _usr_pfault_jmp = current_thread_info()->usr_pfault_jump; \
	set_usr_pfault_jump(); \
	if (likely(current_thread_info()->usr_pfault_jump)) {

#define CATCH_USR_PFAULT \
		E2K_CMD_SEPARATOR; \
		current_thread_info()->usr_pfault_jump = _usr_pfault_jmp; \
	} else { \
		current_thread_info()->usr_pfault_jump = _usr_pfault_jmp;

#define END_USR_PFAULT \
		E2K_CMD_SEPARATOR; \
	}

#define SET_USR_PFAULT(name) \
	unsigned long _usr_pfault_jmp = \
			current_thread_info()->usr_pfault_jump; \
	GET_LBL_ADDR(name, current_thread_info()->usr_pfault_jump)

#define RESTORE_USR_PFAULT \
({ \
	unsigned long __pfault_result = current_thread_info()->usr_pfault_jump;\
	current_thread_info()->usr_pfault_jump = _usr_pfault_jmp; \
	unlikely(!__pfault_result); \
})

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

		/**
		 * 		get user
		 */

extern int __get_user_bad(void) __attribute__((noreturn));

#define __get_user(x, ptr)						\
({									\
	const __typeof__(*(ptr)) __user *___gu_ptr = (ptr);		\
	int __ret_gu;							\
	switch (sizeof(*___gu_ptr)) {					\
	case 1:								\
		GET_USER_ASM(x, ___gu_ptr, b, __ret_gu); break;		\
	case 2:								\
		GET_USER_ASM(x, ___gu_ptr, h, __ret_gu); break;		\
	case 4:								\
		GET_USER_ASM(x, ___gu_ptr, w, __ret_gu); break;		\
	case 8:								\
		GET_USER_ASM(x, ___gu_ptr, d, __ret_gu); break;		\
	default:							\
		__ret_gu = -EFAULT; __get_user_bad(); break;		\
	}								\
	(int) builtin_expect_wrapper(__ret_gu, 0);			\
})

#define get_user(x, ptr)						\
({									\
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
	might_fault();							\
	access_ok(__gu_ptr, sizeof(*__gu_ptr)) ?			\
		__get_user((x), __gu_ptr) : -EFAULT;			\
})


		/**
		 * 		put user
		 */

extern int __put_user_bad(void) __attribute__((noreturn));

#define __put_user(x, ptr)						\
({									\
	__typeof__(*(ptr)) __user *___pu_ptr = (ptr);			\
	__typeof__(*(ptr)) __pu_val  = (x);				\
	int __ret_pu;							\
	switch (sizeof(*___pu_ptr)) {					\
	case 1:								\
		PUT_USER_ASM(__pu_val, ___pu_ptr, b, __ret_pu); break;	\
	case 2:								\
		PUT_USER_ASM(__pu_val, ___pu_ptr, h, __ret_pu); break;	\
	case 4:								\
		PUT_USER_ASM(__pu_val, ___pu_ptr, w, __ret_pu); break;	\
	case 8:								\
		PUT_USER_ASM(__pu_val, ___pu_ptr, d, __ret_pu); break;	\
	default:							\
		__ret_pu = -EFAULT; __put_user_bad(); break;		\
	}								\
	(int) builtin_expect_wrapper(__ret_pu, 0);			\
})

#define put_user(x, ptr)						\
({									\
	__typeof__(*(ptr)) *__pu_ptr = (ptr);				\
	might_fault();							\
	(access_ok(__pu_ptr, sizeof(*__pu_ptr))) ?			\
		__put_user((x), __pu_ptr) : -EFAULT;			\
})

#define raw_copy_to_user	raw_copy_in_user

extern unsigned long raw_copy_from_user(void *to, const void *from,
					unsigned long n);
extern unsigned long raw_copy_in_user(void *to, const void *from,
				      unsigned long n);

#define INLINE_COPY_FROM_USER
#define INLINE_COPY_TO_USER

extern unsigned long __copy_user_with_tags(void *to, const void *from,
					   unsigned long n);

#define __copy_in_user_with_tags	__copy_user_with_tags
#define __copy_to_user_with_tags	__copy_user_with_tags
#define __copy_from_user_with_tags	__copy_user_with_tags

static inline
unsigned long copy_in_user_with_tags(void __user *to, const void __user *from,
				     unsigned long n)
{
	if (likely(access_ok(from, n) && access_ok(to, n)))
		n = __copy_in_user_with_tags(to, from, n);

	return n;
}

static inline
unsigned long copy_to_user_with_tags(void __user *to, const void *from,
				     unsigned long n)
{
	if (access_ok(to, n))
		n = __copy_to_user_with_tags(to, from, n);

	return n;
}

static inline
unsigned long copy_from_user_with_tags(void *to, const void __user *from,
				       unsigned long n)
{
	if (access_ok(from, n))
		n = __copy_from_user_with_tags(to, from, n);

	return n;
}

#define strlen_user(str) strnlen_user(str, ~0UL >> 1)
long strnlen_user(const char __user *str, long count) __pure;

long __strncpy_from_user(char *dst, const char *src, long count);

static inline long
strncpy_from_user(char *dst, const char __user *src, long count)
{
	if (!access_ok(src, 1))
		return -EFAULT;
	return __strncpy_from_user(dst, src, count);
}


unsigned long __fill_user(void __user *mem, unsigned long len, const u8 b);

static inline __must_check unsigned long
fill_user(void __user *to, unsigned long n, const u8 b)
{
	if (!access_ok(to, n))
		return n;

	return __fill_user(to, n, b);
}

#define __clear_user(mem, len) __fill_user(mem, len, 0)
#define clear_user(to, n) fill_user(to, n, 0)


unsigned long __fill_user_with_tags(void *, unsigned long, unsigned long, unsigned long);

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

static inline int PUT_USER_AP(e2k_ptr_t *ptr, u64 base,
        u64 len, u64 off, u64 rw)
{
	if ((long)ptr & 0xf) {
		/* not aligned */
		return -EFAULT;
	}

	TRY_USR_PFAULT {
		if (base == 0) {
			E2K_STORE_NULLPTR_QWORD(&AWP(ptr).lo);
		} else {
        		u64 tmp;

			tmp = MAKE_AP_HI(base, len, off, rw);
			/* FIXME: need implement for guest kernel
			 * to support virtualization */
			NATIVE_STORE_VALUE_WITH_TAG(&AWP(ptr).hi, tmp,
						    E2K_AP_HI_ETAG);
			tmp = MAKE_AP_LO(base, len, off, rw);
			/* FIXME: need implement for guest kernel
			 * to support virtualization */
			NATIVE_STORE_VALUE_WITH_TAG(&AWP(ptr).lo, tmp,
						    E2K_AP_LO_ETAG);
		}
	} CATCH_USR_PFAULT {
                return -EFAULT;
	} END_USR_PFAULT

        return 0;
}

static inline int PUT_USER_PL_V2(e2k_pl_lo_t *plp, u64 entry)
{
	e2k_pl_lo_t tmp = MAKE_PL_V2(entry).lo;

	if ((long)plp & (sizeof(e2k_pl_lo_t) - 1)) {
		/* not aligned */
		return -EFAULT;
	}

	TRY_USR_PFAULT {
		/* FIXME: need implement for guest kernel
		 * to support virtualization */
		NATIVE_STORE_VALUE_WITH_TAG(plp, tmp.PL_lo_value, E2K_PL_ETAG);
	} CATCH_USR_PFAULT {
		return -EFAULT;
	} END_USR_PFAULT

	return 0;
}

static inline int PUT_USER_PL_V6(e2k_pl_t *plp, u64 entry, u32 cui)
{
	e2k_pl_t tmp = MAKE_PL_V6(entry, cui);

	if ((long)plp & (sizeof(e2k_pl_t) - 1)) {
		/* not aligned */
		return -EFAULT;
	}

	TRY_USR_PFAULT {
		/* FIXME: need implement for guest kernel
		 * to support virtualization */
		NATIVE_STORE_TAGGED_QWORD(plp, tmp.PLLO_value, tmp.PLHI_value,
						E2K_PLLO_ETAG, E2K_PLHI_ETAG);
	} CATCH_USR_PFAULT {
		return -EFAULT;
	} END_USR_PFAULT

	return 0;
}

static inline int CPU_PUT_USER_PL(e2k_pl_t *plp, u64 entry, u32 cui,
					bool is_cpu_iset_v6)
{
	if (is_cpu_iset_v6) {
		return PUT_USER_PL_V6(plp, entry, cui);
	} else {
		int ret = put_user(0UL, &plp->PLHI_value);
		if (ret)
			return ret;
		return PUT_USER_PL_V2(&plp->PLLO_item, entry);
	}
}

static inline int PUT_USER_PL(e2k_pl_t *plp, u64 entry, u32 cui)
{
	return CPU_PUT_USER_PL(plp, entry, cui, IS_CPU_ISET_V6());
}

#define __GET_USER_VAL_TAGD(val, tag, ptr)			\
({								\
	int res;						\
	TRY_USR_PFAULT {                                        \
		/* FIXME: should be paravirtualized */		\
		NATIVE_LOAD_VAL_AND_TAGD((ptr), (val), (tag));	\
		res = 0;					\
	} CATCH_USR_PFAULT {					\
		res = -EFAULT;					\
	} END_USR_PFAULT					\
        res;							\
})

#define GET_USER_VAL_TAGD(val, tag, ptr)			\
({								\
	const __typeof__(*(ptr)) __user *__guvt_ptr = (ptr);	\
	access_ok(__guvt_ptr, sizeof(*__guvt_ptr)) ?		\
		__GET_USER_VAL_TAGD((val), (tag), __guvt_ptr) : -EFAULT; \
})

#endif /* CONFIG_PROTECTED_MODE */

#endif /* _E2K_UACCESS_H_ */
