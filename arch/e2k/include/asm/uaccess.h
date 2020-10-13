#ifndef _E2K_UACCESS_H_
#define _E2K_UACCESS_H_

/*
 * User space memory access functions
 * asm/uaccess.h
 */
#include <linux/sched.h>

#include <asm/page.h>
#include <asm/e2k_api.h>
#ifdef CONFIG_PROTECTED_MODE
#include <asm/e2k_ptypes.h>
#endif
#ifdef CONFIG_FAST_ADDRESS_PROBE
#include <asm/mmu_regs_access.h>
#endif

#define VERIFY_READ	0
#define VERIFY_WRITE	1

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

#define KERNEL_DS	MAKE_MM_SEG(0x0001000000000000)
#define USER_DS		MAKE_MM_SEG(USER_HW_STACKS_BASE)

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

#define __access_ok(addr, size, segment)				\
({									\
	__chk_user_ptr(addr);						\
	likely(((e2k_addr_t)(addr) < (segment).seg) &&			\
		((e2k_addr_t)(addr) + (e2k_size_t)(size) <= (segment).seg));\
})
#define access_ok(type,addr,size)       __access_ok((addr), (size), get_fs())


struct exception_table_entry
{
	unsigned long insn;
	unsigned long fixup;
};


/*
 * The macros to work safely in kernel with user's address:
 *
 *                   BEGIN_USR_PFAULT(label, local_label);
 *                   ..... // code which used user's address
 *                   LBL_USR_PFAULT(label, local_label);
 *                   if (END_USR_PFAULT) {
 *                   ...   // was interrupt(bad user's address)  
 *                   }
 * NOTE1: to use this multiple times inside one function add "{" and  "}"
 *	  around the nested usage.
 * NOTE2: Procedures called LBL_USR_PFAULT must be noinline since asm does
 *        not support multple global labels with the same name, and local
 *        labels can mix with eath other within one compilation unit if
 *        the function is inlined.
 * NOTE3: the compiler believes that after global label we CAN"T use
 *        local context so __result__ must be initilazed after the label.
 * NOTE4: Must not use the same local label twice in one compilation unit.
 */                   

#define BEGIN_USR_PFAULT(name, local_name)                              \
	might_fault();							\
        SAVE_USR_PFAULT;                                                \
	GET_LBL_ADDR(name, local_name, _thread_info->usr_pfault_jump);	\
	E2K_CMD_SEPARATOR;

#define LBL_USR_PFAULT(name, local_name) TRAP_RETURN_LABEL(name, local_name)

#define SAVE_USR_PFAULT	struct thread_info *_thread_info =		\
					current_thread_info();		\
			long _usr_pfault_jmp = _thread_info->usr_pfault_jump

#define END_USR_PFAULT \
({ \
	unsigned long __pfault_result = _thread_info->usr_pfault_jump; \
	_thread_info->usr_pfault_jump = _usr_pfault_jmp; \
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

#if __LCC__ >= 120

#define __get_user_size(x,  ptr, size, __ret_gu)			\
do {									\
	__ret_gu = 0;							\
	switch (size) {							\
	case 1:								\
		GET_USER_ASM(x, ptr, b, __ret_gu); break;		\
	case 2:								\
		GET_USER_ASM(x, ptr, h, __ret_gu); break;		\
	case 4:								\
		GET_USER_ASM(x, ptr, w, __ret_gu); break;		\
	case 8:								\
		GET_USER_ASM(x, ptr, d, __ret_gu); break;		\
	default:							\
		__ret_gu = -EFAULT; break;				\
	}								\
									\
} while (0)

#define __get_user_nocheck(x, ptr, size)				\
({									\
	int __ret_gu = 0;						\
	__get_user_size(x, ptr, size, __ret_gu);			\
									\
	__ret_gu;							\
})

#else /* __LCC__ < 120 */

#define __get_user_nocheck(x,  ptr, size)				\
({									\
	int __ret_gu;							\
	BUILD_BUG_ON(size != 1 && size != 2 && size != 4 && size != 8);	\
	SAVE_USR_PFAULT;                                         	\
	current_thread_info()->usr_pfault_jump = PG_JMP;		\
	E2K_CMD_SEPARATOR;						\
	x = *ptr;							\
	E2K_CMD_SEPARATOR;						\
	if (END_USR_PFAULT) {						\
		DebugUAF("%s (%d) - %s : "				\
			"get_user data fault %p(%ld)\n" ,		\
			__FILE__, __LINE__, __FUNCTION__,		\
			(ptr), (size));					\
		__ret_gu = -EFAULT;					\
	} else {							\
		__ret_gu = 0;						\
	}								\
	__ret_gu;							\
})
#endif /* __LCC__ >= 120 */


#define get_user_nocheck(x,ptr)					\
	__get_user_nocheck((x), (ptr), sizeof(*(ptr)))		\


#define get_user(x,ptr)							\
({									\
	const __typeof__(*(ptr)) __user *__ptr = (ptr);			\
	x = 0;								\
	access_ok(VERIFY_READ,  __ptr, sizeof (*(__ptr))) ?		\
		__get_user_nocheck((x), __ptr, sizeof(*(__ptr))) :	\
		-EFAULT;						\
})

#define __get_user(x,ptr)					\
	__get_user_nocheck((x),(ptr),sizeof(*(ptr)))



		/**
		 * 		put user
		 */

#if __LCC__ >= 120

#define __put_user_size(x, ptr, size, retval)				\
do {									\
	retval = 0;							\
	switch (size) {							\
	case 1:								\
		PUT_USER_ASM(x, ptr, b, retval); break;			\
	case 2:								\
		PUT_USER_ASM(x, ptr, h, retval); break;			\
	case 4:								\
		PUT_USER_ASM(x, ptr, w, retval); break;			\
	case 8:								\
		PUT_USER_ASM(x, ptr, d, retval); break;			\
	default:							\
		retval = -EFAULT; break;				\
	}								\
} while (0)

#else
#define __put_user_size(x, ptr, size, retval)			\
do {								\
	BUILD_BUG_ON(size != 1 && size != 2 && size != 4 && size != 8);	\
	SAVE_USR_PFAULT;                                       	\
	retval = 0;						\
	current_thread_info()->usr_pfault_jump = PG_JMP;	\
	DebugUA("%s (%d) - %s : "				\
		"__put_user_size() will put to "		\
		"ptr 0x%p size 0x%lx\n",			\
		__FILE__, __LINE__, __FUNCTION__,		\
		ptr, size);					\
	/* E2K_CMD_SEPARATOR; */				\
	PUT_USER(x, ptr, size, retval);				\
	/* E2K_CMD_SEPARATOR; */				\
	if (END_USR_PFAULT) {					\
		DebugUAF("%s (%d) - %s : "			\
		"__put_user_size interrupted %p(%ld)\n",	\
		__FILE__, __LINE__, __FUNCTION__,		\
			(ptr), (size));				\
		retval = -EFAULT;				\
	}							\
} while (0)

#endif

#define put_user_size(x, ptr, size, __pu_err)			\
({								\
	DebugUA("__put_user_check() entered.\n");		\
	if (access_ok(VERIFY_WRITE, (ptr), (size))) {		\
		__put_user_size((x), (ptr), (size), __pu_err);	\
	} else {						\
		__pu_err = -EACCES;				\
	}							\
	__pu_err;						\
})							

#define put_user(x, ptr)					\
( {								\
	__typeof__ (*(ptr)) *__pu_ptrr = (ptr);			\
	int __pu_errr = 0;					\
	__typeof__(*(ptr)) __pu_val = x;			\
	 put_user_size(__pu_val, __pu_ptrr, sizeof(*__pu_ptrr),	\
		__pu_errr);					\
	__pu_errr;						\
})

#define __put_user(x, ptr)					\
({								\
	__typeof__ (*(ptr)) *__pu_ptr = (ptr);			\
	__typeof__(*(ptr)) __pu_val = x;			\
	int __pu_err = 0;					\
	__put_user_size(__pu_val, __pu_ptr, sizeof(*(__pu_ptr))	\
			, __pu_err);				\
	__pu_err;						\
})


#define generic_copy_to_user generic_copy_in_user
extern unsigned long generic_copy_from_user(void *to,
		                         const void *from,
					 unsigned long n);
extern unsigned long generic_copy_in_user(void *to,
		                         const void *from,
					 unsigned long n);
extern unsigned long __copy_user_with_tags(void *to, const void *from,
					   unsigned long n);

static inline
unsigned long copy_in_user(void __user *to, const void __user *from,
			   unsigned long n)
{
	if (likely(access_ok(VERIFY_READ, from, n) &&
		   access_ok(VERIFY_WRITE, to, n)))
		n = generic_copy_in_user(to, from, n);

	return n;
}

static inline
unsigned long copy_to_user_check(void *to, const void *from, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		n = generic_copy_to_user(to, from, n);

	return n;
}

static inline
unsigned long copy_from_user_check(void *to, const void *from, unsigned long n)
{
	if (access_ok(VERIFY_READ, from, n))
		n = generic_copy_from_user(to, from, n);

	return n;
}

#define copy_to_user(to, from, n)			\
			copy_to_user_check(to, (const void *)(from), n)	
#define copy_from_user(to, from, n)			\
			copy_from_user_check(to, (const void *)(from), n)	
#define __copy_to_user(to, from, n)			\
				generic_copy_to_user(to, (const void *)from, n)
#define __copy_from_user(to, from, n)			\
				generic_copy_from_user(to, (const void *)from, n)

#define __copy_to_user_inatomic		__copy_to_user
#define __copy_from_user_inatomic		__copy_from_user

static inline
unsigned long copy_in_user_with_tags(void __user *to, const void __user *from,
				     unsigned long n)
{
	if (likely(access_ok(VERIFY_READ, from, n) &&
		   access_ok(VERIFY_WRITE, to, n)))
		n = __copy_user_with_tags(to, from, n);

	return n;
}

static inline
unsigned long copy_to_user_with_tags(void __user *to, const void *from,
				     unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		n = __copy_user_with_tags(to, from, n);

	return n;
}

static inline
unsigned long copy_from_user_with_tags(void *to, const void __user *from,
				       unsigned long n)
{
	if (access_ok(VERIFY_READ, from, n))
		n = __copy_user_with_tags(to, from, n);

	return n;
}

#define __copy_in_user_with_tags	__copy_user_with_tags
#define __copy_to_user_with_tags	__copy_user_with_tags
#define __copy_from_user_with_tags	__copy_user_with_tags


#if defined(CONFIG_SERIAL_PRINTK)
#include <asm/console.h>
#define one_char_to_shadow_console(c)   do {                            \
        if(likely(serial_console_opts)) {                               \
                if (c == '\n') {                                        \
                        serial_console_opts->serial_putc('\r');         \
                }                                                       \
                serial_console_opts->serial_putc(c);                    \
        }                                                               \
        } while(0)
#endif

#define strlen_user(str) strnlen_user(str, ~0UL >> 1)
long strnlen_user(const char __user *str, long count);

long __strncpy_from_user(char *dst, const char *src, long count);

static inline long
strncpy_from_user(char *dst, const char __user *src, long count)
{
	if (!access_ok(VERIFY_READ, src, 1))
		return -EFAULT;
	return __strncpy_from_user(dst, src, count);
}

unsigned long __clear_user(void *mem, unsigned long len);

static inline __must_check unsigned long
clear_user(void __user *to, unsigned long n)
{
	if (!access_ok(VERIFY_WRITE, to, n))
		return n;

	return __clear_user(to, n);
}


#ifdef CONFIG_PROTECTED_MODE

static inline   int PUT_USER_AP(e2k_ptr_t *ptr, u64 base,
        u64 len, u64 off, u64 rw)
{
        u64 tmp;
	SAVE_USR_PFAULT; 
	if ((long)ptr & 0xf) {
		/* not aligned */
		return -EFAULT;
	}
	current_thread_info()->usr_pfault_jump = PG_JMP;
        if (base == 0) {
		E2K_STORE_NULLPTR_QWORD(&AWP(ptr).lo);
		if (END_USR_PFAULT) {
                	return -EFAULT;
		}
		/* don't check again because the same page */
		return 0;
        }
        tmp = MAKE_AP_HI(base, len, off, rw);
	E2K_STORE_VALUE_WITH_TAG(&AWP(ptr).hi, tmp, E2K_AP_HI_ETAG);

	if (!current_thread_info()->usr_pfault_jump) {
		END_USR_PFAULT;
                return -EFAULT;
	}
	/* don't check again because the same page */
        tmp = MAKE_AP_LO(base, len, off, rw);
	E2K_STORE_VALUE_WITH_TAG(&AWP(ptr).lo, tmp, E2K_AP_LO_ETAG);
	END_USR_PFAULT;
        return 0;
}


static inline int PUT_AP_TO_USER_AP(e2k_ptr_t *where, e2k_ptr_t what)
{
        u64 tmp;
	SAVE_USR_PFAULT; 
	if ((long)where & 0xf) {
		/* not aligned */
		return -EFAULT;
	}
	current_thread_info()->usr_pfault_jump = PG_JMP;
	if (AS(what).size == 0) {
		AWP(where).lo = 0L;
		if (!current_thread_info()->usr_pfault_jump) {
			END_USR_PFAULT;
                	return -EFAULT;
		}
		/* don't check again because the same page */
		AWP(where).hi = 0L;
		END_USR_PFAULT;
                return 0;
        }
	tmp = AW(what).hi;
	E2K_STORE_VALUE_WITH_TAG(&AWP(where).hi, tmp, E2K_AP_HI_ETAG);
	if (!current_thread_info()->usr_pfault_jump) {
		END_USR_PFAULT;
                return -EFAULT;
	}
	/* don't check again because the same page */ 
	tmp = AW(what).lo;
	E2K_STORE_VALUE_WITH_TAG(&AWP(where).lo, tmp, E2K_AP_LO_ETAG);
	END_USR_PFAULT;
        return 0;
}



static inline   int PUT_USER_PL(e2k_pl_t *plp, u64 entry)
{
        e2k_pl_t tmp = MAKE_PL(entry);
	SAVE_USR_PFAULT; 
	if ((long)plp &0x7) {
		/* not aligned */
		return -EFAULT;
	}
	current_thread_info()->usr_pfault_jump = PG_JMP;
        E2K_STORE_VALUE_WITH_TAG(&plp->word, 
                                       tmp.word, E2K_PL_ETAG);
	if (END_USR_PFAULT)
                return -EFAULT;
        return 0;
}

static inline int
PUT_QUADRO_TAGGED_WORD(char *dst, unsigned long lo_val,
                        unsigned long lo_tag, unsigned long hi_val, unsigned long hi_tag)
{
        unsigned long ap_lo, ap_hi;
        SAVE_USR_PFAULT;

        ap_lo = MAKE_AP_LO((unsigned long) dst, 0x10UL, 0, RW_ENABLE);
        ap_hi = MAKE_AP_HI((unsigned long) dst, 0x10UL, 0, RW_ENABLE);
        current_thread_info()->usr_pfault_jump = PG_JMP;
	asm volatile (  "addd  \t0x0, %0, %%db[2]\n\t"
			"addd  \t0x0, %1, %%db[3]\n\t"

			"addd  \t0x0, %2, %%db[4]\n\t"
			"addd  \t0x0, %3, %%db[5]\n\t"

			"puttagd \t%%db[2], %6, %%db[2]\n\t"
			"puttagd \t%%db[3], %7, %%db[3]\n\t"

			"puttagd \t%%db[4], %4 , %%db[4]\n\t"
			"puttagd \t%%db[5], %5 , %%db[5]\n\t"

			"{ stapq \t%%qb[4], 0x0, %%qb[2]\n\t }"
			:
			: "r" (lo_val), "r" (hi_val), "r" (ap_lo), "r" (ap_hi),
			  "i" (E2K_AP_LO_ETAG), "i" (E2K_AP_HI_ETAG),
			  "r" (lo_tag), "r" (hi_tag)
			: "%b[2]", "%b[3]", "%b[4]", "%b[5]");
	E2K_CMD_SEPARATOR;
	if (END_USR_PFAULT)
		return -EFAULT;

	return 0;
}


static inline int
PUT_DOUBLE_TAGGED_WORD(char *dst, unsigned long val, unsigned long tag)
{
        unsigned long ap_lo, ap_hi;
        SAVE_USR_PFAULT;

        ap_lo = MAKE_AP_LO((unsigned long) dst, 0x08UL, 0, RW_ENABLE);
        ap_hi = MAKE_AP_HI((unsigned long) dst, 0x08UL, 0, RW_ENABLE);

        asm volatile (  "addd  \t0x0, %0, %%db[2]\n\t"
                        "addd  \t0x0, %1, %%db[4]\n\t"
                        "addd  \t0x0, %2, %%db[5]\n\t"
                        "puttagd \t%%db[2], %5, %%db[2]\n\t"
                        "puttagd \t%%db[4], %3 , %%db[4]\n\t"
                        "puttagd \t%%db[5], %4 , %%db[5]\n\t"
                        "{ stapd \t%%qb[4], 0x0, %%db[2]\n\t }"
                        :
                        : "r" (val), "r" (ap_lo), "r" (ap_hi),
                          "i" (E2K_AP_LO_ETAG), "i" (E2K_AP_HI_ETAG), "r" (tag)
                        : "%b[2]", "%b[4]", "%b[5]");
        E2K_CMD_SEPARATOR;
        if (END_USR_PFAULT)
                return -EFAULT;
        return 0;
}

extern int user_atomic_cmpxchg_inatomic(u32 *uval, u32 __user *uaddr,
					u32 oldval, u32 newval, int size);

#define GET_USER_TAGD(tgval, datap)				\
({								\
	int res = 0;						\
	SAVE_USR_PFAULT;                                        \
	current_thread_info()->usr_pfault_jump = PG_JMP;	\
	tgval = E2K_LOAD_TAGD(datap);				\
	E2K_CMD_SEPARATOR;					\
	if (!current_thread_info()->usr_pfault_jump) {		\
		res = -EFAULT;					\
	}							\
	END_USR_PFAULT;                                      \
        res;							\
})

#endif /* CONFIG_PROTECTED_MODE */

#endif /* _E2K_UACCESS_H_ */
