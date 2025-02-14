#ifndef _E2K_KVM_GUEST_UACCESS_H_
#define _E2K_KVM_GUEST_UACCESS_H_

/*
 * Guest User space memory access functions
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
#include <asm/mmu_fault.h>

#define __kvm_get_priv_user(x, ptr)					\
({									\
	const __typeof__(*(ptr)) *___gk_ptr;				\
	struct page *page;						\
	unsigned long u_addr = (unsigned long)(ptr);			\
	unsigned long offset, k_addr;					\
	int __ret_gu;							\
									\
	page = get_user_addr_to_kernel_page(u_addr);			\
	if (unlikely(IS_ERR_OR_NULL(page))) {				\
		__ret_gu = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;	\
	} else {							\
		offset = u_addr & ~PAGE_MASK;				\
		k_addr = (unsigned long)page_address(page) + offset;	\
		___gk_ptr = (const __typeof__(*(ptr)) *)k_addr;		\
		__ret_gu = __get_user(x, ___gk_ptr);			\
		put_user_addr_to_kernel_page(page);			\
	}								\
	(int) builtin_expect_wrapper(__ret_gu, 0);			\
})

#define kvm_get_priv_user(x, ptr)					\
({									\
	const __typeof__(*(ptr)) __user *__gu_ptr = (ptr);		\
	might_fault();							\
	access_ok(__gu_ptr, sizeof(*__gu_ptr)) ?			\
		__kvm_get_priv_user((x), __gu_ptr) :			\
		((x) = (__typeof__(x)) 0, -EFAULT);			\
})

#define __kvm_put_priv_user(x, ptr)					\
({									\
	__typeof__(*(ptr)) *___pk_ptr = (ptr);				\
	struct page *page;						\
	unsigned long u_addr = (unsigned long)(ptr);			\
	unsigned long offset, k_addr;					\
	int __ret_pu;							\
									\
	page = get_user_addr_to_kernel_page(u_addr);			\
	if (unlikely(IS_ERR_OR_NULL(page))) {				\
		__ret_pu = (IS_ERR(page)) ? PTR_ERR(page) : -EINVAL;	\
	} else {							\
		offset = u_addr & ~PAGE_MASK;				\
		k_addr = (unsigned long)page_address(page) + offset;	\
		___pk_ptr = (__typeof__(*(ptr)) *)k_addr;		\
		__ret_pu = __put_user(x, ___pk_ptr);			\
		put_user_addr_to_kernel_page(page);			\
	}								\
	(int) builtin_expect_wrapper(__ret_pu, 0);			\
})

#define kvm_put_priv_user(x, ptr)					\
({									\
	__typeof__(*(ptr)) *__pu_ptr = (ptr);				\
	might_fault();							\
	(access_ok(__pu_ptr, sizeof(*__pu_ptr))) ?			\
		__kvm_put_priv_user((x), __pu_ptr) : -EFAULT;		\
})

extern unsigned long __kvm_copy_to_priv_user(void __user *to, const void *from,
					  unsigned long n);
extern unsigned long __kvm_copy_to_priv_user_with_tags(void __user *to,
					const void *from, unsigned long n);
extern unsigned long __kvm_copy_from_priv_user(void *to,
				const void __user *from, unsigned long n);
extern unsigned long __kvm_copy_from_priv_user_with_tags(void *to,
				const void __user *from, unsigned long n);

static inline
unsigned long kvm_copy_to_priv_user_with_tags(void __user *to, const void *from,
					      unsigned long n)
{
	if (access_ok(to, n))
		n = __kvm_copy_to_priv_user_with_tags(to, from, n);

	return n;
}

static inline
unsigned long kvm_copy_from_priv_user_with_tags(void *to, const void __user *from,
						unsigned long n)
{
	if (access_ok(from, n))
		n = __kvm_copy_from_priv_user_with_tags(to, from, n);

	return n;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is native guest kernel (without paravirtualization) */

#define	__get_priv_user(x, ptr)		__kvm_get_priv_user(x, ptr)
#define __put_priv_user(x, ptr)		__kvm_put_priv_user(x, ptr)
#define	get_priv_user(x, ptr)		kvm_get_priv_user(x, ptr)
#define	put_priv_user(x, ptr)		kvm_put_priv_user(x, ptr)

#define __copy_to_priv_user		__kvm_copy_to_priv_user
#define __copy_from_priv_user		__kvm_copy_from_priv_user
#define __copy_to_priv_user_with_tags	__kvm_copy_to_priv_user_with_tags
#define __copy_from_priv_user_with_tags	__kvm_copy_from_priv_user_with_tags

static inline
unsigned long copy_to_priv_user_with_tags(void __user *to, const void *from,
					  unsigned long n)
{
	return kvm_copy_to_priv_user_with_tags(to, from, n);
}

static inline
unsigned long copy_from_priv_user_with_tags(void *to, const void __user *from,
					    unsigned long n)
{
	return kvm_copy_from_priv_user_with_tags(to, from, n);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#define GET_USER_VAL_AND_TAGW(val, tag, ptr, __ret_gu) \
do { \
	if (IS_HV_GM()) { \
		uaccess_enable(); \
		NATIVE_GET_USER_VAL_AND_TAGW((val), (tag), (ptr), __ret_gu); \
		uaccess_disable(); \
	} else { \
		u8 __tag; \
		__ret_gu = kvm_get_user_val_and_tagw((ptr), &(val), &__tag); \
		if (likely(!__ret_gu)) \
			(tag) = __tag; \
	} \
} while (0)
extern int kvm_get_user_val_and_tagw(const void __user *ptr, u32 *val, u8 *tag);

#define GET_USER_VAL_AND_TAGD(val, tag, ptr, __ret_gu) \
do { \
	if (IS_HV_GM()) { \
		uaccess_enable(); \
		NATIVE_GET_USER_VAL_AND_TAGD((val), (tag), (ptr), __ret_gu); \
		uaccess_disable(); \
	} else { \
		u8 __tag; \
		__ret_gu = kvm_get_user_val_and_tagd((ptr), &(val), &__tag); \
		if (likely(!__ret_gu)) \
			(tag) = __tag; \
	} \
} while (0)
extern int kvm_get_user_val_and_tagd(const void __user *ptr, u64 *val, u8 *tag);

#define GET_USER_VAL_AND_TAGQ(val_lo, val_hi, tag, ptr, __ret_gu, _offset) \
do { \
	if (IS_HV_GM()) { \
		uaccess_enable(); \
		NATIVE_GET_USER_VAL_AND_TAGQ((val_lo), (val_hi), (tag), \
				(ptr), __ret_gu, (_offset)); \
		uaccess_disable(); \
	} else { \
		u8 __tag_lo, __tag_hi; \
		__ret_gu = kvm_get_user_val_and_tagq((ptr), &(val_lo), &(val_hi), \
				&__tag_lo, &__tag_hi, (_offset)); \
		if (likely(!__ret_gu)) \
			(tag) = __tag_lo | (__tag_hi << 4); \
	} \
} while (0)
extern int kvm_get_user_val_and_tagq(const void __user *ptr, u64 *val_lo,
		u64 *val_hi, u8 *tag_lo, u8 *tag_hi, unsigned long offset);

#define PUT_USER_VAL_AND_TAGD(val, tag, ptr, __ret_pu) \
do { \
	if (IS_HV_GM()) { \
		uaccess_enable(); \
		NATIVE_PUT_USER_VAL_AND_TAGD((val), (tag), (ptr), __ret_pu); \
		uaccess_disable(); \
	} else { \
		__ret_pu = kvm_put_user_val_and_tagd(ptr, (u64) (val), (u32) (tag)); \
	} \
} while (0)
extern int kvm_put_user_val_and_tagd(void __user *ptr, u64 val, u32 tag);

#define PUT_USER_VAL_AND_TAGQ(val_lo, val_hi, tag, ptr, __ret_pu, offset) \
do { \
	if (IS_HV_GM()) { \
		uaccess_enable(); \
		NATIVE_PUT_USER_VAL_AND_TAGQ((val_lo), (val_hi), (tag), \
					     (ptr), __ret_pu, (offset)); \
		uaccess_disable(); \
	} else { \
		__ret_pu = kvm_put_user_val_and_tagq((ptr), (u64) (val_lo), \
				(u64) (val_hi), (u32) (tag), (offset)); \
	} \
} while (0)
extern int kvm_put_user_val_and_tagq(void __user *ptr, u64 val_lo, u64 val_hi,
				     u32 tag, unsigned long offset);

#endif /* _E2K_KVM_GUEST_UACCESS_H_ */