#ifndef __ASM_KVM_GUEST_MMU_H
#define __ASM_KVM_GUEST_MMU_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/mmu_regs_types.h>
#include <asm/tlb_regs_types.h>
#include <asm/mmu_fault.h>

extern long kvm_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store);
extern long kvm_recovery_faulted_load(e2k_addr_t address, u64 *ld_val,
				u8 *data_tag, u64 ld_rec_opc, int chan);
extern long kvm_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load);
extern long kvm_recovery_faulted_load_to_greg(e2k_addr_t address,
		u32 greg_num_d, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load,
		void *saved_greg_lo, void *saved_greg_hi);
extern long kvm_move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to);
extern long kvm_move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to);
extern long kvm_move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to);

static inline void
kvm_handle_mpdma_fault(e2k_addr_t hva)
{
	/* model of sic NBSR is not used on guest */
}

static inline bool
kvm_is_guest_kernel_gregs(struct thread_info *ti,
				unsigned greg_num_d, u64 **greg_copy)
{
	if (HOST_KERNEL_GREGS_PAIR_MASK == 0 ||
			!(HOST_KERNEL_GREGS_PAIR_MASK & (1UL << greg_num_d)))
		/* register is not used by host and guest */
		/* to support virtualization */
		return false;

	*greg_copy = ti->h_gregs.g[greg_num_d - HOST_GREGS_PAIRS_START].xreg;
	return true;
}

#ifdef	CONFIG_KVM_GUEST_KERNEL

static inline int
guest_addr_to_host(void **addr, pt_regs_t *regs)
{
	return native_guest_addr_to_host(addr);
}

static inline void *
guest_ptr_to_host(void *ptr, int size, pt_regs_t *regs)
{
	/* there are not any guests, so nothing convertion */
	return native_guest_ptr_to_host(ptr, size);
}

static inline bool
is_guest_kernel_gregs(struct thread_info *ti,
			unsigned greg_num_d, u64 **greg_copy)
{
	return kvm_is_guest_kernel_gregs(ti, greg_num_d, greg_copy);
}
static inline long
recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	if (likely(IS_HV_GM()))
		return native_recovery_faulted_tagged_store(address, wr_data,
				data_tag, st_rec_opc, data_ext, data_ext_tag,
				opc_ext, chan, qp_store, atomic_store);
	else
		return kvm_recovery_faulted_tagged_store(address, wr_data,
				data_tag, st_rec_opc, data_ext, data_ext_tag,
				opc_ext, chan, qp_store, atomic_store);
}
static inline long
recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
					u64 ld_rec_opc, int chan)
{
	if (likely(IS_HV_GM()))
		return native_recovery_faulted_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
	else
		return kvm_recovery_faulted_load(address, ld_val,
					data_tag, ld_rec_opc, chan);
}
static inline long
recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load)
{
	if (likely(IS_HV_GM()))
		return native_recovery_faulted_move(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, chan,
				qp_load, atomic_load);
	else
		return kvm_recovery_faulted_move(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, chan,
				qp_load, atomic_load);
}
static inline long
recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d, int vr,
		u64 ld_rec_opc, int chan, int qp_load, int atomic_load,
		void *saved_greg_lo, void *saved_greg_hi)
{
	if (likely(IS_HV_GM()))
		return native_recovery_faulted_load_to_greg(address, greg_num_d,
				vr, ld_rec_opc, chan, qp_load, atomic_load,
				saved_greg_lo, saved_greg_hi);
	else
		return kvm_recovery_faulted_load_to_greg(address, greg_num_d,
				vr, ld_rec_opc, chan, qp_load, atomic_load,
				saved_greg_lo, saved_greg_hi);
}
static inline long
move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	if (likely(IS_HV_GM()))
		return native_move_tagged_word(addr_from, addr_to);
	else
		return kvm_move_tagged_word(addr_from, addr_to);
}
static inline long
move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	if (likely(IS_HV_GM()))
		return native_move_tagged_dword(addr_from, addr_to);
	else
		return kvm_move_tagged_dword(addr_from, addr_to);
}
static inline long
move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	if (likely(IS_HV_GM()))
		return native_move_tagged_qword(addr_from, addr_to);
	else
		return kvm_move_tagged_qword(addr_from, addr_to);
}

static inline void
handle_mpdma_fault(e2k_addr_t hva)
{
	kvm_handle_mpdma_fault(hva);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_MMU_H */
