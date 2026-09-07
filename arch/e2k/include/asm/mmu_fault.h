/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MMU_FAULT_H_
#define _E2K_MMU_FAULT_H_

#include <linux/threads.h>
#include <linux/errno.h>
#include <asm/mmu_types.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>
#include <asm/e2k_api.h>

#if defined CONFIG_KVM_PARAVIRTUALIZATION || defined CONFIG_KVM_GUEST_KERNEL
static inline void __user *
native_guest_ptr_to_host(void *ptr, int size)
{
	/* there are not any guests, so nothing convertion */
	return (void __user __force *) ptr;
}
#endif

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline bool
native_ftype_has_sw_fault(tc_fault_type_t ftype)
{
	/* software faults are not used by native & host kernel */
	/* but software bit can be set by hardware and it is wrong */
	return !ftype_test_is_kvm_fault_injected(ftype);
}

static inline bool
native_ftype_test_sw_fault(tc_fault_type_t ftype)
{
	return false;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void
native_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, ldst_rec_op_t st_rec_opc, u64 data_ext, u32 data_ext_tag,
		ldst_rec_op_t opc_ext, int chan, int qp_store, int atomic_store)
{
	if (atomic_store) {
		NATIVE_RECOVERY_TAGGED_STORE_ATOMIC(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext);
	} else {
		NATIVE_RECOVERY_TAGGED_STORE(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext,
				chan, qp_store);
	}
}
static inline void
native_recovery_faulted_load(unsigned long address, u64 *ld_val, u8 *data_tag,
			     ldst_rec_op_t ld_rec_opc, int chan)
{
	u64 val;
	u32 tag;

	NATIVE_RECOVERY_TAGGED_LOAD_TO(address, ld_rec_opc, val, tag, chan);
	*ld_val = val;
	*data_tag = tag;
}
static inline void
native_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, ldst_rec_op_t ld_opc, int chan,
		int qp_load, int atomic_load, bool big_endian, bool single_byte,
		bool clear_lo, bool clear_hi, bool spec)
{
	ldst_rec_op_t ld_opc_hi = ld_opc;
	ld_opc_hi.index |= 8;

	if (qp_load && big_endian) {
		swap(ld_opc, ld_opc_hi);
		swap(clear_lo, clear_hi);
	}

	if (atomic_load) {
		native_move_tagged_dword_with_opc_vr_atomic(addr_from, addr_to,
				addr_to_hi, vr, ld_opc, ld_opc_hi);
	} else {
		native_move_tagged_dword_with_opc_ch_vr(addr_from, addr_to, addr_to_hi,
				vr, ld_opc, ld_opc_hi, clear_lo, clear_hi,
				chan, qp_load, single_byte, spec);
	}
}

static inline void
native_recovery_faulted_load_to_cpu_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, ldst_rec_op_t ld_rec_opc, int chan_opc, int qp_load,
		int atomic_load, bool big_endian, bool clear_lo, bool clear_hi,
		bool spec)
{
	u64 opc_lo = AW(ld_rec_opc);
	u64 opc_hi = opc_lo | 8ULL;

	if (qp_load && big_endian) {
		swap(opc_lo, opc_hi);
		swap(clear_lo, clear_hi);
	}

	if (atomic_load) {
		NATIVE_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(address, opc_lo, opc_hi,
				greg_num_d, vr, qp_load);
	} else {
		NATIVE_RECOVERY_LOAD_TO_A_GREG_CH_VR(address, opc_lo, opc_hi,
				clear_lo, clear_hi, greg_num_d, chan_opc, vr, qp_load, spec);
	}
}

static inline void
native_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, ldst_rec_op_t ld_rec_opc, int chan_opc,
		int qp_load, int atomic_load, bool big_endian, u64 *saved_greg_lo,
		u64 *saved_greg_hi, bool clear_lo, bool clear_hi, bool spec)
{
	if (!saved_greg_lo) {
		native_recovery_faulted_load_to_cpu_greg(address,
				greg_num_d, vr, ld_rec_opc, chan_opc, qp_load,
				atomic_load, big_endian, clear_lo, clear_hi, spec);
	} else {
		native_recovery_faulted_move(address,
				(u64) saved_greg_lo, (u64) saved_greg_hi,
				vr, ld_rec_opc, chan_opc, qp_load, atomic_load,
				big_endian, false, clear_lo, clear_hi, spec);
	}
}

static inline bool
native_is_guest_kernel_gregs(struct thread_info *ti,
			unsigned greg_num_d, u64 **greg_copy)
{
	/* native kernel does not use such registers */
	/* host kernel save/restore such registers itself */
	return false;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void
native_move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_WORD(addr_from, addr_to);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
static inline void
native_move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_DWORD(addr_from, addr_to);
}
static inline void
native_move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_QWORD(addr_from, addr_from + sizeof(long),
				addr_to, addr_to + sizeof(long));
}

extern int native_handle_mpdma_fault(e2k_addr_t hva, struct pt_regs *ptregs);

extern void print_address_ptes(pgd_t *pgdp, e2k_addr_t address, int kernel);

/*
 * Virtualization support
 */
#if	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline bool
ftype_has_sw_fault(tc_fault_type_t ftype)
{
	return native_ftype_has_sw_fault(ftype);
}

static inline bool
ftype_test_sw_fault(tc_fault_type_t ftype)
{
	return native_ftype_test_sw_fault(ftype);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void
recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data, u32 data_tag,
		ldst_rec_op_t st_rec_opc, u64 data_ext, u32 data_ext_tag,
		ldst_rec_op_t opc_ext, int chan, int qp_store, int atomic_store)
{
	native_recovery_faulted_tagged_store(address, wr_data, data_tag,
			st_rec_opc, data_ext, data_ext_tag, opc_ext,
			chan, qp_store, atomic_store);
}
static inline void
recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
			ldst_rec_op_t ld_rec_opc, int chan, tc_cond_t cond)
{
	native_recovery_faulted_load(address, ld_val, data_tag, ld_rec_opc, chan);
}
static inline void
recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d, int vr,
		ldst_rec_op_t ld_rec_opc, int chan, int qp_load, int atomic_load,
		bool big_endian, u64 *saved_greg_lo, u64 *saved_greg_hi,
		tc_cond_t cond, bool clear_lo, bool clear_hi, bool spec)
{
	native_recovery_faulted_load_to_greg(address, greg_num_d, vr, ld_rec_opc,
			chan, qp_load, atomic_load, big_endian,
			saved_greg_lo, saved_greg_hi, clear_lo, clear_hi, spec);
}
static inline void
recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to, e2k_addr_t addr_to_hi,
		int vr, ldst_rec_op_t ld_rec_opc, int chan, int qp_load,
		int atomic_load, bool big_endian, bool single_byte, tc_cond_t cond,
		bool clear_lo, bool clear_hi, bool spec)
{
	native_recovery_faulted_move(addr_from, addr_to, addr_to_hi, vr, ld_rec_opc, chan,
			qp_load, atomic_load, big_endian, single_byte, clear_lo, clear_hi, spec);
}

static inline void load_qvalue_and_tagq(const volatile void *address, e2k_qreg_t *val,
					u8 *tag, size_t offset)
{
	NATIVE_LOAD_VAL_AND_TAGQ(address, val->lo, val->hi, *tag, offset);
}

static inline void store_tagged_qword(volatile void *address, e2k_qreg_t data, u8 tag, size_t offset)
{
	NATIVE_STORE_TAGGED_QWORD(address, data.lo, data.hi, tag & 0xf, tag >> 4, offset);
}

/**
 * store_tagged_colored_qword - save 16 bytes of data with both tags and colors
 *
 * Color is specified in high bits of address in hardware format.
 */
static inline void store_tagged_colored_qword(volatile void *address, e2k_qreg_t data, u8 tag)
{
	STORE_TAGGED_COLORED_QWORD(address, data.lo, data.hi, tag & 0xf, tag >> 4);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline bool
is_guest_kernel_gregs(struct thread_info *ti,
			unsigned greg_num_d, u64 **greg_copy)
{
	return native_is_guest_kernel_gregs(ti, greg_num_d, greg_copy);
}
static inline void
move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_word(addr_from, addr_to);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
static inline void
move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_dword(addr_from, addr_to);
}
static inline void
move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_qword(addr_from, addr_to);
}
static inline int
handle_mpdma_fault(e2k_addr_t hva, struct pt_regs *ptregs)
{
	return native_handle_mpdma_fault(hva, ptregs);
}

# ifdef CONFIG_VIRTUALIZATION
/* it is native host kernel with virtualization support */
#include <asm/kvm/mmu.h>
# endif	/* !CONFIG_VIRTUALIZATION */

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/mmu.h>
#else
 #error	"Unknown virtualization type"
#endif	/* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_KERNEL */

static inline void
store_tagged_dword(volatile void *address, u64 data, u32 tag)
{
	auto opcode = ldst_rec_tagged_store();
	recovery_faulted_tagged_store((e2k_addr_t) address, data, tag,
			opcode, 0, 0, opcode, 1, 0, 0);
}

static inline void
load_value_and_tagd(const volatile void *address, u64 *ld_val, u8 *ld_tag)
{
	recovery_faulted_load((e2k_addr_t) address, ld_val, ld_tag,
			ldst_rec_tagged_load(), 0, (tc_cond_t) {.word = 0});
}

#endif /* _E2K_MMU_FAULT_H_ */
