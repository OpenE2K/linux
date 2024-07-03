/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _KVM_STRING_H_
#define _KVM_STRING_H_

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/string.h>
#include <linux/uaccess.h>

#include "mmu.h"
#include "gaccess.h"

static __priv_hypercall inline unsigned long
kvm_priv_tagged_memory_copy(void *dst, const void *src, size_t len,
			    unsigned long strd_opcode, unsigned long ldrd_opcode,
			    bool prefetch)
{
	return native_fast_tagged_memory_copy(dst, src, len,
			(ldst_rec_op_t) { .word = strd_opcode },
			(ldst_rec_op_t) { .word = ldrd_opcode }, prefetch);
}

static __priv_hypercall inline unsigned long
kvm_priv_tagged_memory_set(void *addr, u64 val, u64 tag, size_t len,
			   u64 strd_opcode)
{
	return native_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}

static __priv_hypercall inline unsigned long
kvm_priv_tagged_memory_copy_user(void *dst, const void *src, size_t len,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			bool prefetch)
{
	struct task_struct *p = (struct task_struct *) NATIVE_READ_CURRENT_REG_VALUE();
	unsigned long to_save_usr_pfault_jump;
	unsigned long copied;

	KVM_SET_USR_PFAULT("$recovery_memcpy_fault", p, to_save_usr_pfault_jump);
	copied = native_fast_tagged_memory_copy(dst, src, len,
			(ldst_rec_op_t) { .word = strd_opcode },
			(ldst_rec_op_t) { .word = ldrd_opcode }, prefetch);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);

	return copied;
}

static __priv_hypercall inline unsigned long
kvm_priv_tagged_memory_set_user(void *addr, u64 val, u64 tag, size_t len,
				u64 strd_opcode)
{
	struct task_struct *p = (struct task_struct *) NATIVE_READ_CURRENT_REG_VALUE();
	unsigned long to_save_usr_pfault_jump;
	unsigned long cleared;

	KVM_SET_USR_PFAULT("$recovery_memset_fault", p, to_save_usr_pfault_jump);
	cleared = native_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
	KVM_RESTORE_USR_PFAULT(p, to_save_usr_pfault_jump);

	return cleared;
}

extern long kvm_fast_guest_kernel_tagged_memory_copy_light_hcall(
		struct kvm_vcpu *vcpu, void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode, int prefetch);
extern long kvm_fast_guest_kernel_tagged_memory_set_light_hcall(
		struct kvm_vcpu *vcpu, void *addr, u64 val, u64 tag, size_t len,
		u64 strd_opcode);

/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 * light case: all addresses should be from guest kernel address space,
 * nothing shadow addresses
 */
static inline long
kvm_fast_guest_tagged_memory_copy(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	ldst_rec_op_t ldst_rec_op;
	int ret;

	LD_ST_REC_OPC_reg(ldst_rec_op) = ldrd_opcode;
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		if (!IS_GUEST_PHYS_ADDRESS((e2k_addr_t)src)) {
			pr_err("%s(): bad guest phys src %px ldrd 0x%lx"
				"phys start 0x%lx end 0x%lx\n",
				__func__, src, ldrd_opcode, GUEST_PAGE_OFFSET,
				GUEST_PAGE_OFFSET + MAX_PM_SIZE);
			ret = -EFAULT;
			goto failed;
		}
		LD_ST_REC_OPC_mas(ldst_rec_op) = MAS_LOAD_OPERATION;
		ldrd_opcode = LD_ST_REC_OPC_reg(ldst_rec_op);
	}
	LD_ST_REC_OPC_reg(ldst_rec_op) = LDST_PREFETCH_FLAG_CLEAR(strd_opcode);
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		if (!IS_GUEST_PHYS_ADDRESS((e2k_addr_t)dst)) {
			pr_err("%s(): bad guest phys dst %px ldrd 0x%lx "
				"phys start 0x%lx end 0x%lx\n",
				__func__, dst, strd_opcode, GUEST_PAGE_OFFSET,
				GUEST_PAGE_OFFSET + MAX_PM_SIZE);
			ret = -EFAULT;
			goto failed;
		}
		LD_ST_REC_OPC_mas(ldst_rec_op) = MAS_STORE_OPERATION;
		strd_opcode = LD_ST_REC_OPC_reg(ldst_rec_op);
	}
	return kvm_vcpu_copy_guest_virt_system(vcpu, dst, src, len, copied,
				strd_opcode, ldrd_opcode, prefetch);

failed:
	return ret;
}

static inline long
kvm_fast_guest_tagged_memory_set(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t len, size_t *cleared,
		u64 strd_opcode)
{
	ldst_rec_op_t ldst_rec_op;
	int ret;

	LD_ST_REC_OPC_reg(ldst_rec_op) = strd_opcode;
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		if (!IS_GUEST_PHYS_ADDRESS((e2k_addr_t)addr)) {
			ret = -EFAULT;
			goto failed;
		}
		LD_ST_REC_OPC_mas(ldst_rec_op) = MAS_STORE_OPERATION;
		strd_opcode = LD_ST_REC_OPC_reg(ldst_rec_op);
	}
	return kvm_vcpu_set_guest_virt_system(vcpu, addr, val, tag, len,
						cleared, strd_opcode);

failed:
	return ret;
}

static inline long
kvm_fast_guest_user_tagged_memory_copy(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	ldst_rec_op_t ldst_rec_op;
	int ret;

	LD_ST_REC_OPC_reg(ldst_rec_op) = ldrd_opcode;
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		ret = -EFAULT;
		goto failed;
	}
	LD_ST_REC_OPC_reg(ldst_rec_op) = LDST_PREFETCH_FLAG_CLEAR(strd_opcode);
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		ret = -EFAULT;
		goto failed;
	}
	return kvm_vcpu_copy_guest_user_virt_system(vcpu, dst, src, len, copied,
				strd_opcode, ldrd_opcode, prefetch);

failed:
	return ret;
}

static inline long
kvm_fast_guest_user_tagged_memory_set(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t len, size_t *cleared,
		u64 strd_opcode)
{
	ldst_rec_op_t ldst_rec_op;
	int ret;

	LD_ST_REC_OPC_reg(ldst_rec_op) = strd_opcode;
	if (LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_LOAD_PA ||
		LD_ST_REC_OPC_mas(ldst_rec_op) == MAS_STORE_PA) {
		ret = -EFAULT;
		goto failed;
	}
	return kvm_vcpu_set_guest_user_virt_system(vcpu, addr, val, tag, len,
						   cleared, strd_opcode);

failed:
	return ret;
}

/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 * common case: some addresses can be from host kernel address space,
 * but point to guest structures, shadow image ...
 */
static inline long
kvm_fast_tagged_guest_memory_copy(struct kvm_vcpu *vcpu,
		void *dst, const void *src,
		size_t len, unsigned long strd_opcode,
		unsigned long ldrd_opcode, int prefetch)
{
	return kvm_fast_guest_tagged_memory_copy(vcpu, dst, src, len, NULL,
			strd_opcode, ldrd_opcode, prefetch);
}

static inline long
kvm_copy_from_to_user_with_tags(struct kvm_vcpu *vcpu,
			void __user *dst, void __user *src, size_t len)
{
	unsigned long st_opcode = TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT;
	unsigned long ld_opcode = TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT;

	return kvm_vcpu_copy_guest_virt_system(vcpu, dst, src, len, NULL,
				st_opcode, ld_opcode, 0);
}

/*
 * Extract tags from 32 bytes of data
 */
static inline long
kvm_extract_guest_tags_32(u16 *dst, const void *src)
{
	if (IS_HOST_KERNEL_ADDRESS((e2k_addr_t)src) ||
		IS_HOST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		return -EINVAL;
	}
	if (!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src) ||
		!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		return -EINVAL;
	}
	if (!access_ok(dst, sizeof(u16))) {
		pr_err("%s(): bad dst %px + len 0x%lx addr limit 0x%lx\n",
			__func__, dst, sizeof(u16),
			current_thread_info()->addr_limit.seg);
		return -EFAULT;
	}
	if (!access_ok(src, 32)) {
		pr_err("%s(): bad src %px + len 0x%x addr limit 0x%lx\n",
			__func__, src, 32,
			current_thread_info()->addr_limit.seg);
		return -EFAULT;
	}
	return native_extract_tags_32(dst, src);
}

#endif /* _KVM_STRING_H_ */
