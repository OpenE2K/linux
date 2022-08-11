#ifndef __ASM_PARAVIRT_MMU_H
#define __ASM_PARAVIRT_MMU_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline long
pv_recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data, u32 data_tag,
					u64 st_rec_opc, int chan)
{
	return pv_mmu_ops.recovery_faulted_tagged_store(address, wr_data,
						data_tag, st_rec_opc, chan);
}
static inline long
pv_recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
					u64 ld_rec_opc, int chan)
{
	return pv_mmu_ops.recovery_faulted_load(address, ld_val, data_tag,
							ld_rec_opc, chan);
}
static inline long
pv_recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
			int format, int vr, u64 ld_rec_opc, int chan)
{
	return pv_mmu_ops.recovery_faulted_move(addr_from, addr_to,
						format, vr, ld_rec_opc, chan);
}
static inline long
pv_recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d, int format,
			int vr, u64 ld_rec_opc, int chan, void *saved_greg)
{
	return pv_mmu_ops.recovery_faulted_load_to_greg(address, greg_num_d,
				format, vr, ld_rec_opc, chan, saved_greg);
}

static inline bool
pv_is_guest_kernel_gregs(struct thread_info *ti,
			unsigned greg_num_d, u64 **greg_copy)
{
	if (!paravirt_enabled())
		return native_is_guest_kernel_gregs(ti, greg_num_d, greg_copy);
	else
		return kvm_is_guest_kernel_gregs(ti, greg_num_d, greg_copy);
}
static inline void
pv_move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_mmu_ops.move_tagged_word(addr_from, addr_to);
}
static inline void
pv_move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_mmu_ops.move_tagged_dword(addr_from, addr_to);
}
static inline void
pv_move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_mmu_ops.move_tagged_qword(addr_from, addr_to);
}
static inline void
pv_save_DAM(unsigned long long dam[DAM_ENTRIES_NUM])
{
	pv_mmu_ops.save_DAM(dam);
}

#ifdef	CONFIG_PARAVIRT_GUEST
static inline long
recovery_faulted_tagged_store(e2k_addr_t address, u64 wr_data,
					u32 data_tag, u64 st_rec_opc, int chan)
{
	return pv_recovery_faulted_tagged_store(address, wr_data, data_tag,
							st_rec_opc, chan);
}
static inline long
recovery_faulted_load(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
					u64 ld_rec_opc, int chan)
{
	return pv_recovery_faulted_load(address, ld_val, data_tag,
						ld_rec_opc, chan);
}
static inline long
recovery_faulted_move(e2k_addr_t addr_from, e2k_addr_t addr_to,
			int format, int vr, u64 ld_rec_opc, int chan)
{
	return pv_recovery_faulted_move(addr_from, addr_to, format, vr,
						ld_rec_opc, chan);
}
static inline long
recovery_faulted_load_to_greg(e2k_addr_t address, u32 greg_num_d,
		int format, int vr, u64 ld_rec_opc, int chan, void *saved_greg)
{
	return pv_recovery_faulted_load_to_greg(address, greg_num_d,
				format, vr, ld_rec_opc, chan, saved_greg);
}
static inline bool
is_guest_kernel_gregs(struct thread_info *ti,
			unsigned greg_num_d, u64 **greg_copy)
{
	return pv_is_guest_kernel_gregs(ti, greg_num_d, greg_copy);
}
static inline void
move_tagged_word(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_move_tagged_word(addr_from, addr_to);
}
static inline void
move_tagged_dword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_move_tagged_dword(addr_from, addr_to);
}
static inline void
move_tagged_qword(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	pv_move_tagged_qword(addr_from, addr_to);
}

static inline void
save_DAM(unsigned long long dam[DAM_ENTRIES_NUM])
{
	pv_save_DAM(dam);
}
#define	SAVE_DAM(dam)	save_DAM(dam)

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_MMU_H */
