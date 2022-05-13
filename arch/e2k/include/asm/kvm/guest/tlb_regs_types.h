#ifndef __ASM_KVM_GUEST_TLB_REGS_TYPES_H
#define __ASM_KVM_GUEST_TLB_REGS_TYPES_H

#ifdef __KERNEL__

#include <linux/types.h>

#include <asm/mmu_regs_types.h>
#include <asm/tlb_regs_types.h>

extern probe_entry_t kvm_mmu_entry_probe(e2k_addr_t virt_addr);
extern probe_entry_t kvm_mmu_address_probe(e2k_addr_t virt_addr);
extern mmu_reg_t kvm_read_dtlb_reg(e2k_addr_t virt_addr);

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_TLB_REGS_TYPES_H */
