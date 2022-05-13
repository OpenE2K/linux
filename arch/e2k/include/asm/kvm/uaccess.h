#ifndef _E2K_KVM_UACCESS_H_
#define _E2K_KVM_UACCESS_H_

/*
 * Host kernel access to User space memory, including guest user space
 * Copyright (c) 2020, MCST.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/types.h>

#include <asm/page.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <asm/kvm/pv-emul.h>
#include <asm/kvm/mmu.h>

static inline unsigned long
native_copy_in_user_with_tags(void __user *to, const void __user *from,
				unsigned long n)
{
	return __copy_in_user_with_tags(to, from, n);
}

static inline unsigned long
native_copy_to_user_with_tags(void __user *to, const void *from,
				unsigned long n)
{
	return __copy_to_user_with_tags(to, from, n);
}

static inline unsigned long
native_copy_from_user_with_tags(void *to, const void __user *from,
				unsigned long n)
{
	return __copy_from_user_with_tags(to, from, n);
}

#define	native_get_user(kval, uptr)	get_user(kval, uptr)
#define	native_put_user(kval, uptr)	put_user(kval, uptr)

#ifdef	CONFIG_KVM_HOST_MODE
/* it is host kernel with virtualization support */

#define	host_get_guest_kernel(kval, gk_ptr)				\
({									\
	__typeof__(*(gk_ptr)) __user *___pu_ptr;			\
	int sz_uptr = sizeof(*(gk_ptr));				\
	long res;							\
									\
	___pu_ptr = kvm_guest_ptr_to_host_ptr((gk_ptr), false,		\
						sz_uptr, true);		\
	if (PTR_ERR(___pu_ptr) == -EAGAIN)				\
		res = -EAGAIN;						\
	else								\
		res = (___pu_ptr) ? native_get_user(kval, ___pu_ptr) :	\
					-EFAULT;			\
	(res);								\
})

#define	host_put_guest_kernel(kval, gk_ptr)				\
({									\
	__typeof__(*(gk_ptr)) __user *___pu_ptr;			\
	int sz_uptr = sizeof(*(gk_ptr));				\
	long res;							\
									\
	___pu_ptr = kvm_guest_ptr_to_host_ptr((gk_ptr), true,		\
						sz_uptr, true);		\
	if (PTR_ERR(___pu_ptr) == -EAGAIN)				\
		res = -EAGAIN;						\
	else								\
		res = (___pu_ptr) ? native_put_user(kval, ___pu_ptr) :	\
					-EFAULT;			\
	(res);								\
})

#define	host_get_user(kval, uptr, hregs)				\
({									\
	__typeof__(*(uptr)) __user *__pu_ptr = (uptr);			\
	long res;							\
									\
	res = (!host_test_intc_emul_mode(hregs)) ?			\
			((__pu_ptr) ?					\
				native_get_user(kval, __pu_ptr)	\
				:					\
				-EFAULT)				\
			:						\
			host_get_guest_kernel(kval, __pu_ptr);		\
	(res);								\
})

#define	host_put_user(kval, uptr, hregs)				\
({									\
	__typeof__(*(uptr)) __user *__pu_ptr = (uptr);			\
	int sz_uptr = sizeof(*(uptr));					\
	long res;							\
									\
	res = (!host_test_intc_emul_mode(hregs)) ?			\
			(__pu_ptr) ?					\
				native_put_user(kval, __pu_ptr)	\
				:					\
				-EFAULT)				\
			:						\
			host_put_guest_kernel(kval, __pu_ptr);		\
	(res);								\
})

#define	__kvm_get_guest(__slot, gfn, __hk_ptr, offset,			\
					gk_ptrp, __writable)		\
({									\
	__typeof__(__hk_ptr) __user *gk_ptr;				\
	unsigned long addr;						\
	int r;								\
									\
	addr = gfn_to_hva_memslot_prot(__slot, gfn, __writable);	\
	if (unlikely(kvm_is_error_hva(addr))) {				\
		r = -EFAULT;						\
	} else {							\
		gk_ptr = (__typeof__((__hk_ptr)) *)(addr + offset);	\
		gk_ptrp = gk_ptr;					\
		r = __get_user((__hk_ptr), gk_ptr);			\
	}								\
	r;								\
})

#define	kvm_get_guest(kvm, gpa, _hk_ptr)				\
({									\
	gfn_t gfn = (gpa) >> PAGE_SHIFT;				\
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);	\
	int offset = offset_in_page(gpa);				\
	__typeof__(_hk_ptr) __user *unused;				\
	int r;								\
									\
	__kvm_get_guest(slot, gfn, (_hk_ptr), offset, unused, NULL);	\
})

#define	kvm_vcpu_get_guest_ptr(vcpu, gpa, _hk_ptr, _gk_ptrp, _writable)	\
({									\
	gfn_t gfn = (gpa) >> PAGE_SHIFT;				\
	struct kvm_memory_slot *slot;					\
	int offset = offset_in_page(gpa);				\
	int r;								\
									\
	slot = kvm_vcpu_gfn_to_memslot(vcpu, gfn);			\
	r = __kvm_get_guest(slot, gfn, (_hk_ptr), offset,		\
					_gk_ptrp, _writable);		\
	r;								\
})
#define	kvm_vcpu_get_guest(vcpu, gpa, ___hk_ptr)			\
({									\
	__typeof__(___hk_ptr) __user *unused;				\
									\
	kvm_vcpu_get_guest_ptr(vcpu, gpa, ___hk_ptr, unused, NULL);	\
})

#define	kvm_get_guest_atomic(kvm, gpa, __hk_ptr)			\
({									\
	__typeof__(__hk_ptr) __user *gk_ptr;				\
	gfn_t gfn = (gpa) >> PAGE_SHIFT;				\
	struct kvm_memory_slot *slot = gfn_to_memslot(kvm, gfn);	\
	int offset = offset_in_page(gpa);				\
	bool writable;							\
	unsigned long addr;						\
	int r;								\
									\
	addr = gfn_to_hva_memslot_prot(slot, gfn, &writable);		\
	if (unlikely(kvm_is_error_hva(addr))) {				\
		r = -EFAULT;						\
	} else {							\
		gk_ptr = (__typeof__((__hk_ptr)) *)(addr + offset);	\
		pagefault_disable();					\
		r = native_get_user((__hk_ptr), gk_ptr);		\
		pagefault_enable();					\
	}								\
	r;								\
})

extern unsigned long kvm_copy_in_user_with_tags(void __user *to,
				const void __user *from, unsigned long n);
extern unsigned long kvm_copy_to_user_with_tags(void __user *to,
				const void *from, unsigned long n);
extern unsigned long kvm_copy_from_user_with_tags(void *to,
				const void __user *from, unsigned long n);

static inline unsigned long
host_copy_in_user_with_tags(void __user *to, const void __user *from,
				unsigned long n, const struct pt_regs *regs)
{
	if (likely(!host_test_intc_emul_mode(regs))) {
		return native_copy_in_user_with_tags(to, from, n);
	}
	return kvm_copy_in_user_with_tags(to, from, n);
}

static inline unsigned long
host_copy_to_user_with_tags(void __user *to, const void *from,
				unsigned long n, const struct pt_regs *regs)
{
	if (likely(!host_test_intc_emul_mode(regs))) {
		return native_copy_to_user_with_tags(to, from, n);
	}
	return kvm_copy_to_user_with_tags(to, from, n);
}

static inline unsigned long
host_copy_from_user_with_tags(void *to, const void __user *from,
				unsigned long n, const struct pt_regs *regs)
{
	if (likely(!host_test_intc_emul_mode(regs))) {
		return native_copy_from_user_with_tags(to, from, n);
	}
	return kvm_copy_from_user_with_tags(to, from, n);
}

extern int kvm_vcpu_copy_host_to_guest(struct kvm_vcpu *vcpu,
		const void *host, void __user *guest, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);
extern int kvm_vcpu_copy_host_from_guest(struct kvm_vcpu *vcpu,
		void *host, const void __user *guest, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);

static inline int
fast_tagged_memory_copy_to_user(void __user *dst, const void *src,
		size_t len, size_t *copied, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	struct kvm_vcpu *vcpu;

	if (likely(!host_test_intc_emul_mode(regs))) {
		return native_fast_tagged_memory_copy_to_user(dst, src,
				len, regs,
				strd_opcode, ldrd_opcode, prefetch);
	}

	vcpu = native_current_thread_info()->vcpu;
	KVM_BUG_ON(vcpu == NULL);
	return kvm_vcpu_copy_host_to_guest(vcpu, src, dst, len,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline int
fast_tagged_memory_copy_from_user(void *dst, const void __user *src,
		size_t len, size_t *copied, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	struct kvm_vcpu *vcpu;

	if (likely(!host_test_intc_emul_mode(regs))) {
		return native_fast_tagged_memory_copy_from_user(dst, src,
				len, regs,
				strd_opcode, ldrd_opcode, prefetch);
	}

	vcpu = native_current_thread_info()->vcpu;
	KVM_BUG_ON(vcpu == NULL);
	return kvm_vcpu_copy_host_from_guest(vcpu, dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
#else	/* !CONFIG_KVM_HOST_MODE */
/* it is not host kernel, it is native kernel without virtualization */

#define	host_get_user(kval, uptr, hregs)	native_get_user(kval, uptr)
#define	host_put_user(kval, uptr, hregs)	native_put_user(kval, uptr)

static inline unsigned long
host_copy_in_user_with_tags(void __user *to, const void __user *from,
				unsigned long n, const struct pt_regs *regs)
{
	return native_copy_in_user_with_tags(to, from, n);
}

static inline unsigned long
host_copy_to_user_with_tags(void __user *to, const void *from,
				unsigned long n, const struct pt_regs *regs)
{
	return native_copy_to_user_with_tags(to, from, n);
}

static inline unsigned long
host_copy_from_user_with_tags(void *to, const void __user *from,
				unsigned long n, const struct pt_regs *regs)
{
	return native_copy_from_user_with_tags(to, from, n);
}
#endif	/* CONFIG_KVM_HOST_MODE */

static inline unsigned long
host_copy_to_user(void __user *to, const void *from,
				unsigned long n, const struct pt_regs *regs)
{
	return host_copy_to_user_with_tags(to, from, n, regs);
}

#endif /* _E2K_KVM_UACCESS_H_ */
