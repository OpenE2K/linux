#ifndef _E2K_MMU_FAULT_H_
#define _E2K_MMU_FAULT_H_

#include <linux/threads.h>
#include <linux/errno.h>
#include <linux/topology.h>
#include <asm/mmu_types.h>
#include <asm/mmu_regs.h>
#include <asm/machdep.h>
#include <asm/e2k_api.h>

#undef	DEBUG_PA_MODE
#undef	DebugPA
#define	DEBUG_PA_MODE		0	/* page table allocation */
#define	DebugPA(fmt, args...)						\
({									\
	if (DEBUG_PA_MODE)						\
		pr_info(fmt, ##args);					\
})

static inline int
native_guest_addr_to_host(void **addr)
{
	/* there are not any guests, so nothing convertion */
	return 0;
}

static inline void *
native_guest_ptr_to_host(void *ptr, int size)
{
	/* there are not any guests, so nothing convertion */
	return ptr;
}

static inline long
native_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
		u32 data_tag, u64 st_rec_opc, u64 data_ext, u32 data_ext_tag,
		u64 opc_ext, int chan, int qp_store, int atomic_store)
{
	if (atomic_store) {
		NATIVE_RECOVERY_TAGGED_STORE_ATOMIC(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext);
	} else {
		NATIVE_RECOVERY_TAGGED_STORE(address, wr_data, data_tag,
				st_rec_opc, data_ext, data_ext_tag, opc_ext,
				chan, qp_store);
	}

	return 0;
}
static inline long
native_recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
				u64 ld_rec_opc, int chan)
{
	u64 val;
	u32 tag;

	NATIVE_RECOVERY_TAGGED_LOAD_TO(address, ld_rec_opc, val, tag, chan);
	*ld_val = val;
	*data_tag = tag;
	return 0;
}
static inline long
native_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load)
{
	if (atomic_load) {
		NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_VR_ATOMIC(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc);
	} else {
		NATIVE_MOVE_TAGGED_DWORD_WITH_OPC_CH_VR(addr_from, addr_to,
				addr_to_hi, vr, ld_rec_opc, chan, qp_load);
	}

	return 0;
}

static inline long
native_recovery_faulted_load_to_cpu_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan_opc,
		int qp_load, int atomic_load)
{
	if (atomic_load) {
		NATIVE_RECOVERY_LOAD_TO_A_GREG_VR_ATOMIC(address,
				ld_rec_opc, greg_num_d, vr, qp_load);
	} else {
		NATIVE_RECOVERY_LOAD_TO_A_GREG_CH_VR(address,
				ld_rec_opc, greg_num_d, chan_opc, vr, qp_load);
	}

	return 0;
}

static inline long
native_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan_opc,
		int qp_load, int atomic_load, u64 *saved_greg_lo,
		u64 *saved_greg_hi)
{
	if (!saved_greg_lo) {
		return native_recovery_faulted_load_to_cpu_greg(address,
				greg_num_d, vr, ld_rec_opc, chan_opc, qp_load,
				atomic_load);
	} else {
		return native_recovery_faulted_move(address,
				(u64) saved_greg_lo, (u64) saved_greg_hi,
				vr, ld_rec_opc, chan_opc, qp_load, atomic_load);
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

static inline long
native_move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_WORD(addr_from, addr_to);

	return 0;
}
static inline long
native_move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_DWORD(addr_from, addr_to);

	return 0;
}
static inline long
native_move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	NATIVE_MOVE_TAGGED_QWORD(addr_from, addr_from + sizeof(long),
				addr_to, addr_to + sizeof(long));

	return 0;
}

extern void native_handle_mpdma_fault(e2k_addr_t hva);

extern e2k_addr_t print_address_ptes(pgd_t *pgdp, e2k_addr_t address,
					int kernel);


/*
 * Paravirtualization support
 */
#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
static inline long
recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data, u32 data_tag,
		u64 st_rec_opc, u64 data_ext, u32 data_ext_tag, u64 opc_ext,
		int chan, int qp_store, int atomic_store)
{
	return native_recovery_faulted_tagged_store(address, wr_data, data_tag,
			st_rec_opc, data_ext, data_ext_tag, opc_ext,
			chan, qp_store, atomic_store);
}
static inline long
recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
					u64 ld_rec_opc, int chan)
{
	return native_recovery_faulted_load(address, ld_val, data_tag,
						ld_rec_opc, chan);
}
static inline long
recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load, u64 *saved_greg_lo,
		u64 *saved_greg_hi)
{
	return native_recovery_faulted_load_to_greg(address, greg_num_d,
			vr, ld_rec_opc, chan, qp_load, atomic_load,
			saved_greg_lo, saved_greg_hi);
}
static inline long
recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
		e2k_addr_t addr_to_hi, int vr, u64 ld_rec_opc, int chan,
		int qp_load, int atomic_load)
{
	return native_recovery_faulted_move(addr_from, addr_to, addr_to_hi, vr,
			ld_rec_opc, chan, qp_load, atomic_load);
}

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
static inline void
handle_mpdma_fault(e2k_addr_t hva)
{
	native_handle_mpdma_fault(hva);
}

# ifndef CONFIG_VIRTUALIZATION
/* it is native kernel without any virtualization */
static inline int guest_addr_to_host(void **addr, pt_regs_t *regs)
{
	return native_guest_addr_to_host(addr);
}

static inline void *guest_ptr_to_host(void *ptr, int size, pt_regs_t *regs)
{
	return native_guest_ptr_to_host(ptr, size);
}
# else	/* CONFIG_VIRTUALIZATION */
/* it is native host kernel with virtualization support */
#include <asm/kvm/mmu.h>
# endif	/* !CONFIG_VIRTUALIZATION */

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/mmu.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/mmu.h>
#else
 #error	"Unknown virtualization type"
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

static inline long
store_tagged_dword(void *address, u64 data, u32 tag)
{
	return recovery_faulted_tagged_store((e2k_addr_t) address, data, tag,
			TAGGED_MEM_STORE_REC_OPC, 0, 0, 0, 1, 0, 0);
}

static inline long
load_value_and_tagd(const void *address, u64 *ld_val, u8 *ld_tag)
{
	return recovery_faulted_load((e2k_addr_t) address, ld_val, ld_tag,
					TAGGED_MEM_LOAD_REC_OPC, 0);
}

static inline long
load_qvalue_and_tagq(e2k_addr_t address, u64 *val_lo, u64 *val_hi,
			u8 *tag_lo, u8 *tag_hi)
{
	long ret;

	ret = recovery_faulted_load(address, val_lo, tag_lo,
					TAGGED_MEM_LOAD_REC_OPC, 0);
	ret |= recovery_faulted_load(address + sizeof(long), val_hi, tag_hi,
					TAGGED_MEM_LOAD_REC_OPC, 0);
	return ret;
}

#endif /* _E2K_MMU_FAULT_H_ */
