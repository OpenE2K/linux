/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Guest virtual and physical memory access to read from/write to
 * Based on arch/x86/kvm/x86.c code
 */

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>

#include "gaccess.h"
#include "cpu.h"
#include "mmu.h"
#include "intercepts.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COPY_MODE
#undef	DebugCOPY
#define	DEBUG_KVM_COPY_MODE	0	/* copy guest memory debugging */
#define	DebugCOPY(fmt, args...)						\
({									\
	if (DEBUG_KVM_COPY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HOST_USER_COPY_MODE
#undef	DebugHUCOPY
#define	DEBUG_KVM_HOST_USER_COPY_MODE	0	/* copy host to/from user */
						/* memory debugging */
#define	DebugHUCOPY(fmt, args...)					\
({									\
	if (DEBUG_KVM_HOST_USER_COPY_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HOST_GUEST_COPY_MODE
#undef	DebugHGCOPY
#define	DEBUG_KVM_HOST_GUEST_COPY_MODE	0	/* copy host to/from guest */
						/* memory debugging */
#define	DebugHGCOPY(fmt, args...)					\
({									\
	if (DEBUG_KVM_HOST_GUEST_COPY_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static int kvm_vcpu_read_guest_virt_helper(gva_t addr, void *val,
				unsigned int bytes, struct kvm_vcpu *vcpu,
				u32 access, kvm_arch_exception_t *exception)
{
	void *data = val;

	while (bytes) {
		gpa_t gpa = kvm_mmu_gva_to_gpa(vcpu, addr, access, exception);
		unsigned offset = addr & ~PAGE_MASK;
		unsigned toread = min(bytes, (unsigned)PAGE_SIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return -EFAULT;
		ret = kvm_vcpu_read_guest_page(vcpu, gpa_to_gfn(gpa), data,
						offset, toread);
		if (ret < 0) {
			pr_err("%s(): could not read data from guest virt "
				"addr 0x%lx (phys 0x%llx), size 0x%x\n",
				__func__, addr, gpa, bytes);
			return ret;
		}
		bytes -= toread;
		data += toread;
		addr += toread;
	}
	return 0;
}

static int kvm_vcpu_read_guest_phys_helper(struct kvm_vcpu *vcpu,
				gpa_t gpa, void *val, unsigned int bytes)
{
	void *data = val;
	unsigned offset = gpa & ~PAGE_MASK;
	int ret;

	ret = kvm_vcpu_read_guest_page(vcpu, gpa_to_gfn(gpa), data,
					offset, bytes);
	if (ret < 0) {
		pr_err("%s(): could not read data from guest phys addr 0x%llx, "
			"size 0x%x\n",
			__func__, gpa, bytes);
	}
	return ret;
}

static void kvm_vcpu_do_inject_page_fault(struct kvm_vcpu *vcpu, void *addr,
			kvm_arch_exception_t *exception, bool copy_user)
{
	trap_cellar_t tcellar;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	u32 error_code;

	AW(cond) = 0;
	AS(cond).fmt = LDST_BYTE_FMT;
	AW(ftype) = 0;

	E2K_KVM_BUG_ON(!exception->error_code_valid);

	error_code = exception->error_code;
	if (error_code & PFERR_ONLY_VALID_MASK) {
		AS(ftype).page_miss = 1;
	} else if (error_code & PFERR_WRITE_MASK) {
		AS(cond).store = 1;
		AS(ftype).nwrite_page = 1;
	} else if (exception->error_code & PFERR_IS_UNMAPPED_MASK) {
		AS(ftype).illegal_page = 1;
	}
	AS(cond).fault_type = AW(ftype);
	AS(cond).chan = 1;

	/* should be after setting 'fault type' field */
	cond = tc_set_as_kvm_injected(cond, copy_user);

	tcellar.address = (e2k_addr_t)addr;
	tcellar.condition = cond;
	tcellar.data = 0;

	kvm_inject_pv_vcpu_tc_entry(vcpu, &tcellar);
	kvm_inject_data_page_exc_on_IP(vcpu, exception->ip);
	kvm_inject_guest_traps_wish(vcpu, exc_data_page_num);
}

void kvm_vcpu_inject_page_fault(struct kvm_vcpu *vcpu, void *addr,
				kvm_arch_exception_t *exception)
{
	kvm_vcpu_do_inject_page_fault(vcpu, addr, exception, false);
}

static void kvm_vcpu_inject_copy_user_page_fault(struct kvm_vcpu *vcpu, void *addr,
			kvm_arch_exception_t *exception, bool copy_user)
{
	kvm_vcpu_do_inject_page_fault(vcpu, addr, exception, copy_user);
}

/* can be used for instruction fetching */
int kvm_vcpu_fetch_guest_virt(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes)
{
	kvm_arch_exception_t exception = {
		error_code_valid : 0,
	};
	unsigned offset;
	int ret;

	/* Inline kvm_vcpu_read_guest_virt_helper for speed.  */
	gpa_t gpa = kvm_mmu_gva_to_gpa_fetch(vcpu, addr, &exception);
	if (unlikely(gpa == UNMAPPED_GVA))
		return -EFAULT;

	offset = addr & ~PAGE_MASK;
	if (WARN_ON(offset + bytes > PAGE_SIZE))
		bytes = (unsigned)PAGE_SIZE - offset;
	ret = kvm_vcpu_read_guest_page(vcpu, gpa_to_gfn(gpa), val,
					offset, bytes);
	if (unlikely(ret < 0)) {
		pr_err("%s(): could not read data from guest virt addr 0x%lx "
			"(phys 0x%llx), size 0x%x\n",
			__func__, addr, gpa, bytes);
		return ret;
	}
	if (unlikely(exception.error_code_valid)) {
		pr_err("%s(): exception on read data from guest virt "
			"addr 0x%lx (phys 0x%llx), size 0x%x\n",
			__func__, addr, gpa, bytes);
		return -EFAULT;
	}
	return 0;
}

int kvm_vcpu_read_guest_virt_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes)
{
	kvm_arch_exception_t exception = {
		error_code_valid : 0,
	};
	int ret;

	ret = kvm_vcpu_read_guest_virt_helper(addr, val, bytes, vcpu, 0,
			&exception);
	if (ret < 0)
		return ret;

	if (unlikely(exception.error_code_valid)) {
		pr_err("%s(): exception on read data from guest virt "
			"addr 0x%lx, size 0x%x\n",
			__func__, addr, bytes);
		return -EFAULT;
	}
	return 0;
}

int kvm_vcpu_read_guest_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes)
{
	int ret;

	if (kvm_mmu_gva_is_gpa_range(vcpu, addr, bytes)) {
		ret = kvm_vcpu_read_guest_phys_helper(
				vcpu, (gpa_t)addr, val, bytes);
	} else if (kvm_mmu_gva_is_gvpa_range(vcpu, addr, bytes)) {
		gpa_t gpa;

		gpa = kvm_mmu_gvpa_to_gpa(addr);
		ret = kvm_vcpu_read_guest_phys_helper(vcpu, gpa, val, bytes);
	} else {
		ret = kvm_vcpu_read_guest_virt_system(vcpu, addr, val, bytes);
	}

	return ret;
}

int kvm_vcpu_write_guest_virt_system(struct kvm_vcpu *vcpu,
				gva_t addr, void *val, unsigned int bytes)
{
	void *data = val;
	kvm_arch_exception_t exception = {
		error_code_valid : 0,
	};

	while (bytes) {
		gpa_t gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, &exception);
		if (arch_is_error_gpa(gpa)) {
			DebugKVM("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", addr);
			kvm_vcpu_inject_page_fault(vcpu, (void *)addr,
						&exception);
			return -EAGAIN;
		}
		unsigned offset = addr & ~PAGE_MASK;
		unsigned towrite = min(bytes, (unsigned)PAGE_SIZE - offset);
		int ret;

		ret = kvm_vcpu_write_guest_page(vcpu, gpa_to_gfn(gpa), data,
						offset, towrite);
		if (ret < 0) {
			pr_err("%s(): could not write data to guest virt "
				"addr 0x%lx (phys 0x%llx), size 0x%x\n",
				__func__, addr, gpa, towrite);
			return ret;
		}

		bytes -= towrite;
		data += towrite;
		addr += towrite;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(kvm_vcpu_write_guest_virt_system);

static int kvm_vcpu_write_guest_phys_system(struct kvm_vcpu *vcpu,
				gpa_t gpa, void *val, unsigned int bytes)
{
	void *data = val;
	unsigned offset = gpa & ~PAGE_MASK;
	int ret;

	ret = kvm_vcpu_write_guest_page(vcpu, gpa_to_gfn(gpa), data,
					offset, bytes);
	if (ret < 0) {
		pr_err("%s(): could not write data to guest phys addr 0x%llx, "
			"size 0x%x\n",
			__func__, gpa, bytes);
	}
	return ret;
}

int kvm_vcpu_write_guest_system(struct kvm_vcpu *vcpu,
			gva_t addr, void *val, unsigned int bytes)
{
	long ret;

	if (kvm_mmu_gva_is_gpa_range(vcpu, addr, bytes)) {
		ret = kvm_vcpu_write_guest_phys_system(vcpu, (gpa_t)addr, val,
							bytes);
	} else if (kvm_mmu_gva_is_gvpa_range(vcpu, addr, bytes)) {
		gpa_t gpa;

		gpa = kvm_mmu_gvpa_to_gpa(addr);
		ret = kvm_vcpu_write_guest_phys_system(vcpu, gpa, val, bytes);
	} else {
		ret = kvm_vcpu_write_guest_virt_system(vcpu, addr, val, bytes);
	}

	return ret;
}

static long kvm_vcpu_do_set_guest_virt_system(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t size, size_t *cleared,
		u64 strd_opcode, bool copy_user)
{
	size_t len = size;
	long set = 0;
	unsigned long memset_ret;
	kvm_arch_exception_t exception;
	long ret;

	while (len) {
		void *haddr;
		long offset;
		long towrite;
		hva_t hva;

		hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)addr, true, &exception);
		if (kvm_is_error_hva(hva)) {
			DebugKVM("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", addr);
			kvm_vcpu_inject_copy_user_page_fault(vcpu, (void *)addr,
						&exception, copy_user);
			ret = -EAGAIN;
			goto return_fault;
		}

		haddr = (void *)hva;
		offset = hva & ~PAGE_MASK;
		towrite = min(len, (unsigned)PAGE_SIZE - offset);

		if (!access_ok(haddr, towrite)) {
			ret = -EFAULT;
			goto return_fault;
		}
		SET_USR_PFAULT("$recovery_memset_fault", false);
		memset_ret = recovery_memset_8(haddr, val, tag,
						towrite, strd_opcode);
		if (RESTORE_USR_PFAULT(false)) {
			ret = -EFAULT;
			goto return_fault;
		}
		if (memset_ret < towrite) {
			pr_err("%s(): could not set data to guest virt "
				"addr %px host addr %px, size 0x%lx, "
				"error %ld\n", __func__, addr, haddr,
				towrite, memset_ret);
			goto return_cleared_bytes;
		}

		len -= towrite;
		addr += towrite;
		set += towrite;
	}

return_cleared_bytes:
	if (cleared != NULL) {
		if (unlikely(kvm_vcpu_copy_to_guest(vcpu, cleared, &set,
							sizeof(*cleared)))) {
			pr_err("%s(): copy number of cleared bytes to guest "
				"failed\n", __func__);
			return -EFAULT;
		}
	}
	return set;

return_fault:
	if (cleared != NULL) {
		if (unlikely(kvm_vcpu_copy_to_guest(vcpu, cleared, &set,
							sizeof(*cleared)))) {
			pr_err("%s(): copy number of cleared bytes to guest "
				"failed\n", __func__);
			return -EFAULT;
		}
	}
	return ret;
}

long kvm_vcpu_set_guest_virt_system(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t size, size_t *cleared,
		u64 strd_opcode)
{
	return kvm_vcpu_do_set_guest_virt_system(vcpu, addr, val, tag, size,
				cleared, strd_opcode, false);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_set_guest_virt_system);

long kvm_vcpu_set_guest_user_virt_system(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t size, size_t *cleared,
		u64 strd_opcode)
{
	return kvm_vcpu_do_set_guest_virt_system(vcpu, addr, val, tag, size,
				cleared, strd_opcode, true);
}

static inline long copy_aligned_guest_virt_system(struct kvm_vcpu *vcpu,
			void __user *dst, const void __user *src,
			size_t size, size_t *copied_p,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			int prefetch, int ALIGN, bool copy_user)
{
	size_t len = size;
	long copied = 0;
	void *dst_arg = dst;
	const void *src_arg = src;
	void *haddr_dst = NULL, *haddr_src = NULL;
	int to_dst = 0, to_src = 0, off, tail;
	bool is_dst_len = true, is_src_len = true;
	unsigned long memcpy_ret;
	kvm_arch_exception_t exception;
	long ret;

	/* src can be not aligned */
	off = (u64)src & (ALIGN - 1);

	DebugCOPY("started to copy from %px to %px, size 0x%lx\n",
		src, dst, size);

	/* dst & size should be 'ALIGN'-bytes aligned */
	E2K_KVM_BUG_ON(((u64)dst & (ALIGN - 1)) != 0);
	E2K_KVM_BUG_ON((size & (ALIGN - 1)) != 0);

	while (len) {
		unsigned offset_dst, offset_src;
		int towrite;
		hva_t hva_dst, hva_src;

		if (is_dst_len) {
			E2K_KVM_BUG_ON(to_dst != 0);
			hva_dst = kvm_vcpu_gva_to_hva(vcpu, (gva_t)dst,
							true, &exception);
			if (kvm_is_error_hva(hva_dst)) {
				DebugCOPY("failed to find GPA for dst %lx GVA,"
					" inject page fault to guest\n", dst);
				kvm_vcpu_inject_copy_user_page_fault(vcpu,
					(void *)dst, &exception, copy_user);
				ret = -EAGAIN;
				goto return_fault;
			}

			haddr_dst = (void *)hva_dst;
			offset_dst = hva_dst & ~PAGE_MASK;
			to_dst = min(len, (unsigned)PAGE_SIZE - offset_dst);
			DebugCOPY("dst %px hva %px offset 0x%x size 0x%x\n",
				dst, haddr_dst, offset_dst, to_dst);
			E2K_KVM_BUG_ON((to_dst & (ALIGN - 1)) != 0);
		}
		if (is_src_len) {
			E2K_KVM_BUG_ON(to_src > 0);

			hva_src = kvm_vcpu_gva_to_hva(vcpu, (gva_t)src,
							false, &exception);
			if (kvm_is_error_hva(hva_src)) {
				DebugCOPY("failed to find GPA for dst %lx GVA,"
					" inject page fault to guest\n", src);
				kvm_vcpu_inject_copy_user_page_fault(vcpu,
					(void *)src, &exception, copy_user);
				ret = -EAGAIN;
				goto return_fault;
			}

			haddr_src = (void *)hva_src;
			if (unlikely(to_src < 0)) {
				int ret;

				/*
				 * Current src address crosses the page
				 * boundaries and 'tail' bytes at the ending
				 * of the previous page were already copied,
				 * so copy remaining 'off' bytes at the
				 * begining of the next page
				 */
				E2K_KVM_BUG_ON(to_dst < off);
				ret = copy_in_user(haddr_dst, haddr_src, off);
				if (ret) {
					ret = -EFAULT;
					goto return_fault;
				}
				DebugCOPY("copy %d page off bytes from %px "
					"to %px\n",
					off, haddr_src, haddr_dst);
				len -= off;
				dst += off;
				src += off;
				haddr_dst += off;
				haddr_src += off;
				hva_src += off;
				to_dst -= off;
				copied += off;
				to_src = 0;
				DebugCOPY("len 0x%lx dst %px 0x%x "
					"src %px 0x%x\n",
					len, haddr_dst, to_dst,
					haddr_src, to_src);
				if (len == 0)
					break;
			}
			offset_src = hva_src & ~PAGE_MASK;
			if (len <= (unsigned)PAGE_SIZE - offset_src) {
				to_src = len;
				tail = 0;
			} else {
				to_src = (unsigned)PAGE_SIZE - offset_src;
				tail = (off) ? ALIGN - off : 0;
				to_src -= tail;
			}
			DebugCOPY("src %px hva %px offset 0x%x size 0x%x\n",
				src, haddr_src, offset_src, to_src);
			E2K_KVM_BUG_ON((to_src & (ALIGN - 1)) != 0);
		}

		if (unlikely(to_src < ALIGN && tail != 0)) {
			/*
			 * Current src address crosses the page boundaries
			 * and the remaining' tail' bytes at the ending of the
			 * page should be copied as separate bytes
			 */
			E2K_KVM_BUG_ON(to_src != 0);
			E2K_KVM_BUG_ON(to_dst < tail);
			ret = copy_in_user(haddr_dst, haddr_src, tail);
			if (ret) {
				ret = -EFAULT;
				goto return_fault;
			}
			DebugCOPY("copy %d page tail bytes from %px to %px\n",
				tail, haddr_src, haddr_dst);
			len -= tail;
			dst += tail;
			src += tail;
			haddr_dst += tail;
			haddr_src += tail;
			to_dst -= tail;
			to_src -= tail;
			copied += tail;
			tail = 0;
			DebugCOPY("len 0x%lx dst %px 0x%x src %px 0x%x\n",
				len, haddr_dst, to_dst, haddr_src, to_src);
			is_src_len = true;
			E2K_KVM_BUG_ON(to_dst <= 0);
			is_dst_len = false;
			continue;
		}

		if (to_src + tail < to_dst) {
			towrite = to_src;
			is_src_len = true;
			is_dst_len = false;
		} else if (to_src + tail > to_dst) {
			towrite = to_dst;
			is_src_len = false;
			is_dst_len = true;
		} else {
			towrite = to_src;
			is_src_len = true;
			is_dst_len = true;
		}

		DebugCOPY("copy from %px to %px size 0x%x\n",
			haddr_src, haddr_dst, towrite);
		E2K_KVM_BUG_ON((towrite & (ALIGN - 1)) != 0 || len == 0);
		if (towrite) {
			/* fast copy 'ALIGN'-bytes aligned and */
			/* within one page dst and src areas */
			if (!access_ok(haddr_dst, towrite) ||
					!access_ok(haddr_src, towrite)) {
				ret = -EFAULT;
				goto return_fault;
			}

			if (trace_host_copy_hva_area_enabled())
				trace_host_copy_hva_area(haddr_dst, haddr_src,
							 towrite);

			SET_USR_PFAULT("$recovery_memcpy_fault", false);
			memcpy_ret = recovery_memcpy_8(haddr_dst, haddr_src,
					towrite, strd_opcode, ldrd_opcode,
					prefetch);
			if (RESTORE_USR_PFAULT(false)) {
				ret = -EFAULT;
				goto return_fault;
			}
			if (trace_host_hva_area_line_enabled()) {
				trace_host_hva_area((u64 *)haddr_src, memcpy_ret);
				trace_host_hva_area((u64 *)haddr_dst, memcpy_ret);
			}
			if (memcpy_ret < towrite) {
				pr_err("%s(): could not copy data to guest "
					"virt addr %px host addr %px, from "
					"guest virt addr %px host addr %px "
					"size 0x%x, error %ld\n",
					__func__, dst, haddr_dst,
					src, haddr_src, towrite, memcpy_ret);
				goto return_copied_bytes;
			}

			len -= towrite;
			dst += towrite;
			src += towrite;
			haddr_dst += towrite;
			haddr_src += towrite;
			to_dst -= towrite;
			to_src -= towrite;
			copied += towrite;
			DebugCOPY("len 0x%lx dst %px 0x%x src %px 0x%x\n",
				len, haddr_dst, to_dst, haddr_src, to_src);
			if (len == 0)
				break;
		}
	}

	E2K_KVM_BUG_ON(len != 0);
	E2K_KVM_BUG_ON(src != src_arg + size);
	E2K_KVM_BUG_ON(dst != dst_arg + size);

return_copied_bytes:
	if (copied_p != NULL) {
		if (unlikely(kvm_vcpu_copy_to_guest(vcpu, copied_p, &copied,
							sizeof(*copied_p)))) {
			pr_err("%s(): copy number of copied bytes to guest "
				"failed\n", __func__);
			return -EFAULT;
		}
	}
	return copied;

return_fault:
	if (copied_p != NULL) {
		if (unlikely(kvm_vcpu_copy_to_guest(vcpu, copied_p, &copied,
							sizeof(*copied_p)))) {
			pr_err("%s(): copy number of copied bytes to guest "
				"failed\n", __func__);
			return -EFAULT;
		}
	}
	return ret;
}

long kvm_vcpu_copy_guest_virt_system(struct kvm_vcpu *vcpu,
		void __user *dst, const void __user *src,
		size_t size, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return copy_aligned_guest_virt_system(vcpu, dst, src, size, copied,
				strd_opcode, ldrd_opcode, prefetch, 8, false);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_copy_guest_virt_system);

long kvm_vcpu_copy_guest_virt_system_16(struct kvm_vcpu *vcpu,
		void __user *dst, const void __user *src, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return copy_aligned_guest_virt_system(vcpu, dst, src, size, NULL,
				strd_opcode, ldrd_opcode, prefetch, 16, false);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_copy_guest_virt_system_16);

long kvm_vcpu_copy_guest_user_virt_system(struct kvm_vcpu *vcpu,
		void __user *dst, const void __user *src,
		size_t size, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return copy_aligned_guest_virt_system(vcpu, dst, src, size, copied,
				strd_opcode, ldrd_opcode, prefetch, 8, true);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_copy_guest_user_virt_system);

long kvm_vcpu_copy_guest_user_virt_system_16(struct kvm_vcpu *vcpu,
		void __user *dst, const void __user *src, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return copy_aligned_guest_virt_system(vcpu, dst, src, size, NULL,
				strd_opcode, ldrd_opcode, prefetch, 16, true);
}
EXPORT_SYMBOL_GPL(kvm_vcpu_copy_guest_user_virt_system_16);

static size_t kvm_vcpu_copy_host_guest(struct kvm_vcpu *vcpu,
		void *host, void __user *guest, size_t size, bool to_host,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	size_t len = size, quad, head, head_len, tail, ret;
	unsigned long hva;
	void *dst_addr = NULL, *src_addr = NULL, *guest_addr = NULL;
	unsigned guest_off, hva_len = 0;
	kvm_arch_exception_t exception;

	if (to_host) {
		dst_addr = host;
		DebugHGCOPY("started to copy from guest %px to host %px, "
			"size 0x%lx\n", guest, host, size);
	} else {
		src_addr = host;
		DebugHGCOPY("started to copy from host %px to guest %px, "
			"size 0x%lx\n", host, guest, size);
	}

	/* dst can be not quad aligned, but it must be aligned
	 * when copying with tags */
	head = (16 - ((unsigned long) dst_addr & 0xf)) & 0xf;
	head = min(head, len);

	/* copy not quad aligned head of transfered data */
	while (head) {
		hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)guest,
						!to_host, &exception);
		if (kvm_is_error_hva(hva)) {
			DebugHGCOPY("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", guest);
			kvm_vcpu_inject_page_fault(vcpu, (void *)guest,
						&exception);
			return -EAGAIN;
		}

		guest_addr = (void *)hva;
		if (to_host)
			src_addr = guest_addr;
		else
			dst_addr = guest_addr;
		guest_off = (u64)guest_addr & ~PAGE_MASK;
		hva_len = (unsigned)PAGE_SIZE - guest_off;
		head_len = min(head, hva_len);

		DebugHGCOPY("copy head from %px to %px, size 0x%lx\n",
				src_addr, dst_addr, head_len);
		if (to_host) {
			ret = copy_from_user(dst_addr, src_addr, head_len);
		} else {
			ret = copy_to_user(dst_addr, src_addr, head_len);
		}
		if (ret) {
			pr_err("%s(): could not copy 0x%lx bytes from %px to %px, not copied 0x%lx bytes\n",
				__func__, head_len, src_addr, dst_addr, ret);
			return -EFAULT;
		}

		dst_addr += head_len;
		src_addr += head_len;
		guest += head_len;
		host += head_len;
		hva_len -= head_len;
		head -= head_len;
		len -= head_len;
		DebugHGCOPY("len 0x%lx dst %px src %px hva len 0x%x\n",
			len, dst_addr, src_addr, hva_len);
	};

	if (unlikely(len == 0))
		goto out;

	/* now dst & size should be quad aligned */
	E2K_KVM_BUG_ON(((u64)dst_addr & (16 - 1)) != 0);
	tail = len & (16 - 1);
	quad = len - tail;
	if (unlikely(quad == 0))
		goto tail_copy;

	while (quad) {
		size_t quad_len, quad_tail;

		if (hva_len == 0) {
			hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)guest,
							!to_host, &exception);
			if (kvm_is_error_hva(hva)) {
				DebugHGCOPY("failed to find GPA for dst %lx "
					"GVA, inject page fault to guest\n",
					guest);
				kvm_vcpu_inject_page_fault(vcpu, (void *)guest,
							&exception);
				return -EAGAIN;
			}

			guest_addr = (void *)hva;
			if (to_host)
				src_addr = guest_addr;
			else
				dst_addr = guest_addr;
			guest_off = (u64)guest_addr & ~PAGE_MASK;
			hva_len = (unsigned)PAGE_SIZE - guest_off;
		}

		quad_len = min(quad, hva_len);
		quad_tail = quad_len & (16 - 1);
		quad_len -= quad_tail;
		if (unlikely(quad_len == 0))
			goto quad_tail_copy;

		DebugHGCOPY("copy from %px to %px size 0x%lx\n",
			src_addr, dst_addr, quad_len);
		if (!access_ok(guest_addr, quad_len)) {
			pr_err("%s(): guest HVA %px, size 0x%lx is bad\n",
				__func__, guest_addr, quad_len);
			return -EFAULT;
		}
		/* fast copy quad aligned and within one page of guest */
		SET_USR_PFAULT("$recovery_memcpy_fault", false);
		ret = recovery_memcpy_8(dst_addr, src_addr, quad_len,
				strd_opcode, ldrd_opcode, prefetch);
		if (RESTORE_USR_PFAULT(false))
			return -EFAULT;
		if (ret < quad_len) {
			pr_err("%s(): could not copy 0x%lx bytes from %px to %px, not copied 0x%lx bytes\n",
				__func__, quad_len, src_addr, dst_addr, ret);
			return -EFAULT;
		}
		dst_addr += quad_len;
		src_addr += quad_len;
		guest += quad_len;
		host += quad_len;
		hva_len -= quad_len;
		quad -= quad_len;
		len -= quad_len;
		DebugHGCOPY("len 0x%lx dst %px src %px hva len 0x%x\n",
			len, dst_addr, src_addr, hva_len);

quad_tail_copy:
		if (likely(quad_tail == 0))
			continue;

		do {
			size_t tail_len;

			if (hva_len == 0) {
				hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)guest,
							!to_host, &exception);
				if (kvm_is_error_hva(hva)) {
					DebugHGCOPY("failed to find GPA for "
						"dst %lx GVA, inject page "
						"fault to guest\n", guest);
					kvm_vcpu_inject_page_fault(vcpu,
							(void *)guest,
							&exception);
					return -EAGAIN;
				}

				guest_addr = (void *)hva;
				if (to_host)
					src_addr = guest_addr;
				else
					dst_addr = guest_addr;
				guest_off = (u64)guest_addr & ~PAGE_MASK;
				hva_len = (unsigned)PAGE_SIZE - guest_off;
			}
			tail_len = min(quad_tail, hva_len);
			DebugHGCOPY("copy quad tail from %px to %px, size 0x%lx\n",
				src_addr, dst_addr, tail_len);
			if (to_host) {
				ret = copy_from_user(dst_addr, src_addr, tail_len);
			} else {
				ret = copy_to_user(dst_addr, src_addr, tail_len);
			}
			if (ret) {
				pr_err("%s(): could not copy 0x%lx bytes from %px to %px, not copied 0x%lx bytes\n",
					__func__, tail_len, src_addr, dst_addr, ret);
				return -EFAULT;
			}
			dst_addr += tail_len;
			src_addr += tail_len;
			guest += tail_len;
			host += tail_len;
			hva_len -= tail_len;
			quad_tail -= tail_len;
			len -= tail_len;
			DebugHGCOPY("len 0x%lx dst %px src %px hva len 0x%x\n",
				len, dst_addr, src_addr, hva_len);
		} while (quad_tail > 0);
	}
	if (likely(len == 0))
		goto out;

tail_copy:
	if (likely(tail == 0))
		goto out;

	/* copy not quad aligned tail of transfered data */
	do {
		size_t tail_len;

		if (hva_len == 0) {
			hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t)guest,
						!to_host, &exception);
			if (kvm_is_error_hva(hva)) {
				DebugHGCOPY("failed to find GPA for dst %lx "
					"GVA, inject page fault to guest\n",
					guest);
				kvm_vcpu_inject_page_fault(vcpu, (void *)guest,
							&exception);
				return -EAGAIN;
			}

			guest_addr = (void *)hva;
			if (to_host)
				src_addr = guest_addr;
			else
				dst_addr = guest_addr;
			guest_off = (u64)guest_addr & ~PAGE_MASK;
			hva_len = (unsigned)PAGE_SIZE - guest_off;
		}
		tail_len = min(tail, hva_len);
		DebugHGCOPY("copy tail from %px to %px, size 0x%lx\n",
			src_addr, dst_addr, tail_len);
		if (to_host) {
			ret = copy_from_user(dst_addr, src_addr, tail_len);
		} else {
			ret = copy_to_user(dst_addr, src_addr, tail_len);
		}
		if (ret) {
			pr_err("%s(): could not copy 0x%lx bytes from %px to %px, not copied 0x%lx bytes\n",
				__func__, tail_len, src_addr, dst_addr, ret);
			return -EFAULT;
		}
		dst_addr += tail_len;
		src_addr += tail_len;
		guest += tail_len;
		host += tail_len;
		hva_len -= tail_len;
		tail -= tail_len;
		len -= tail_len;
		DebugHGCOPY("len 0x%lx dst %px src %px hva len 0x%x\n",
			len, dst_addr, src_addr, hva_len);
	} while (tail > 0);

out:
	return size;
}

size_t kvm_vcpu_copy_host_to_guest(struct kvm_vcpu *vcpu,
		const void *host, void __user *guest, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_vcpu_copy_host_guest(vcpu, (void *)host, guest, size,
				false, strd_opcode, ldrd_opcode, prefetch);
}

size_t kvm_vcpu_copy_host_from_guest(struct kvm_vcpu *vcpu,
		void *host, const void __user *guest, size_t size,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_vcpu_copy_host_guest(vcpu, host, (void __user *)guest, size,
				true, strd_opcode, ldrd_opcode, prefetch);
}

unsigned long kvm_copy_in_user_with_tags(void __user *to,
			const void __user *from, unsigned long n)
{
	void __user *dst_addr, *src_addr;
	unsigned long len, head, tail, quad;
	long ret;

	dst_addr = to;
	src_addr = (void __user *)from;
	len = n;

	/* dst can be not quad aligned, but it must be aligned
	 * when copying with tags */
	head = (16 - ((unsigned long) dst_addr & 0xf)) & 0xf;
	head = min(head, len);
	ret = copy_aligned_guest_virt_system(current_thread_info()->vcpu,
			dst_addr, src_addr, head, NULL,
			TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			false /* prefetch */, 1, false);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			pr_err("%s(): head copying from %px to %px 0x%lx bytes "
				"failed with error %ld\n",
				__func__, src_addr, dst_addr, head, ret);
		}
		return ret;
	} else if (ret != head) {
		pr_err("%s(): head copying from %px to %px 0x%lx bytes failed, "
			"only %ld bytes were copied\n",
			__func__, src_addr, dst_addr, head, ret);
		return ret;
	}

	dst_addr += head;
	src_addr += head;
	len -= head;

	if (unlikely(len == 0))
		goto out;
	if (len < 16)
		goto tail_copy;

	/* now dst & size should be quad aligned */
	E2K_KVM_BUG_ON(((u64)dst_addr & (16 - 1)) != 0);
	tail = len & (16 - 1);
	quad = len - tail;
	if (unlikely(quad == 0))
		goto tail_copy;

	ret = copy_aligned_guest_virt_system(current_thread_info()->vcpu,
			dst_addr, src_addr, quad, NULL,
			TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			true /* prefetch */, 16, false);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			pr_err("%s(): aligned copying from %px to %px 0x%lx bytes "
				"failed with error %ld\n",
				__func__, src_addr, dst_addr, quad, ret);
		}
		return ret;
	} else if (ret != quad) {
		pr_err("%s(): aligned copying from %px to %px 0x%lx bytes failed, "
			"only %ld bytes were copied\n",
			__func__, src_addr, dst_addr, quad, ret);
		return ret;
	}

	dst_addr += quad;
	src_addr += quad;
	len -= quad;

tail_copy:
	if (likely(len == 0))
		goto out;

	E2K_KVM_BUG_ON(len >= 16);

	ret = copy_aligned_guest_virt_system(current_thread_info()->vcpu,
			dst_addr, src_addr, len, NULL,
			TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
			false /* prefetch */, 1, false);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			pr_err("%s(): tail copying from %px to %px 0x%lx bytes "
				"failed with error %ld\n",
				__func__, src_addr, dst_addr, len, ret);
		}
		return ret;
	} else if (ret != len) {
		pr_err("%s(): tail copying from %px to %px 0x%lx bytes failed, "
			"only %ld bytes were copied\n",
			__func__, src_addr, dst_addr, len, ret);
		return ret;
	}

out:
	return 0;
}

unsigned long kvm_copy_to_user_with_tags(void *__user to,
			const void *from, unsigned long n)
{
	struct kvm_vcpu *vcpu = native_current_thread_info()->vcpu;
	kvm_arch_exception_t exception;

	if (unlikely(((long) to & 0x7) || ((long) from & 0x7) || (n & 0x7))) {
		DebugHUCOPY("%s(): to=%px from=%px n=%ld\n",
				__func__, to, from, n);
		return n;
	}

	while (n) {
		size_t left, copy_len, hva_off;
		__user void *dst;

		hva_t to_hva = kvm_vcpu_gva_to_hva(vcpu, (__force gva_t) to,
						true, &exception);
		if (kvm_is_error_hva(to_hva)) {
			DebugHUCOPY("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", to);
			kvm_vcpu_inject_page_fault(vcpu, (void *)to,
						&exception);
			return -EAGAIN;
		}

		hva_off = to_hva & ~PAGE_MASK;
		copy_len = min((size_t)PAGE_SIZE - hva_off, n);

		DebugHUCOPY("copy from %px to %lx size 0x%lx\n",
			from, to_hva, copy_len);
		E2K_KVM_BUG_ON(copy_len <= 0);
		/* We are working with guest kernel's stacks which are
		 * located below usual hardware stacks area (USER_ADDR_MAX),
		 * thus there is no need to bypass access_ok() check. */
		dst = (__user void *) to_hva;
		left = copy_to_user_with_tags(dst, from, copy_len);
		if (unlikely(left)) {
			pr_err("%s(): error: copied 0x%lx/0x%lx bytes from %px to %px\n",
					__func__, copy_len - left, copy_len, from, to);
			return n - (copy_len - left);
		}

		to += copy_len;
		from += copy_len;
		n -= copy_len;
	}

	return 0;
}

unsigned long kvm_copy_from_user_with_tags(void *to,
			const void __user *from, unsigned long n)
{
	struct kvm_vcpu *vcpu = native_current_thread_info()->vcpu;
	kvm_arch_exception_t exception;

	if (unlikely(((long) to & 0x7) || ((long) from & 0x7) || (n & 0x7))) {
		DebugHUCOPY("%s(): to=%px from=%px n=%ld\n",
				__func__, to, from, n);
		return n;
	}

	while (n) {
		size_t left, copy_len, hva_off;

		hva_t from_hva = kvm_vcpu_gva_to_hva(vcpu,
				(__force gva_t) from, false, &exception);
		if (kvm_is_error_hva(from_hva)) {
			DebugHUCOPY("failed to find GPA for dst %lx GVA, "
				"inject page fault to guest\n", from);
			kvm_vcpu_inject_page_fault(vcpu, (void *)from,
						&exception);
			return -EAGAIN;
		}

		hva_off = from_hva & ~PAGE_MASK;
		copy_len = min((size_t)PAGE_SIZE - hva_off, n);

		DebugHUCOPY("copy from %lx to %px size 0x%lx\n",
				from_hva, to, copy_len);
		E2K_KVM_BUG_ON(copy_len <= 0);
		/* We are working with guest kernel's stacks which are
		 * located below usual hardware stacks area (USER_ADDR_MAX),
		 * thus there is no need to bypass access_ok() check. */
		left = copy_from_user_with_tags(to, (__user void *) from_hva, copy_len);
		if (unlikely(left)) {
			pr_err("%s(): error: copied 0x%lx/0x%lx bytes from %px to %px\n",
					__func__, copy_len - left, copy_len, from, to);
			return n - (copy_len - left);
		}

		to += copy_len;
		from += copy_len;
		n -= copy_len;
	}

	return 0;
}

int kvm_read_guest_phys_system(struct kvm *kvm, gpa_t gpa, void *val,
			unsigned int bytes)
{
	unsigned offset = gpa & ~PAGE_MASK;
	int ret;

	if (WARN_ON_ONCE(offset + bytes > PAGE_SIZE))
		return -EINVAL;

	ret = kvm_read_guest_page(kvm, gpa_to_gfn(gpa), val, offset, bytes);
	if (ret < 0) {
		pr_err("%s(): could not read data from guest phys addr 0x%llx, "
			"size 0x%x\n",
			__func__, gpa, bytes);
	}
	return ret;
}

int kvm_write_guest_phys_system(struct kvm *kvm, gpa_t gpa, void *val,
			unsigned int bytes)
{
	unsigned offset = gpa & ~PAGE_MASK;
	int ret;

	if (WARN_ON_ONCE(offset + bytes > PAGE_SIZE))
		return -EINVAL;

	ret = kvm_write_guest_page(kvm, gpa_to_gfn(gpa), val, offset, bytes);
	if (ret < 0) {
		pr_err("%s(): could not write data to guest phys addr 0x%llx, "
			"size 0x%x\n",
			__func__, gpa, bytes);
	}
	return ret;
}
