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

#define	host_get_user(kval, uptr, hregs)				\
({									\
	__typeof__(*(uptr)) __user *___pu_ptr = (uptr);			\
	int sz_uptr = sizeof(*(uptr));					\
									\
	___pu_ptr = (!host_test_intc_emul_mode(hregs)) ?		\
			(uptr)						\
			:						\
			kvm_guest_ptr_to_host_ptr((uptr), sz_uptr);	\
	(___pu_ptr) ? native_get_user(kval, ___pu_ptr) : -EFAULT;	\
})

#define	host_put_user(kval, uptr, hregs)				\
({									\
	__typeof__(*(uptr)) __user *___pu_ptr = (uptr);			\
	int sz_uptr = sizeof(*(uptr));					\
									\
	___pu_ptr = (!host_test_intc_emul_mode(hregs)) ?		\
			(uptr)						\
			:						\
			kvm_guest_ptr_to_host_ptr((uptr), sz_uptr);	\
	(___pu_ptr) ? native_put_user(kval, ___pu_ptr) : -EFAULT;	\
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
		size_t len, const struct pt_regs *regs,
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
		size_t len, const struct pt_regs *regs,
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
