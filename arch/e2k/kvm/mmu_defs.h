/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_MMU_DEFS_H
#define __KVM_E2K_MMU_DEFS_H

#include <linux/kvm_host.h>
#include <asm/mmu_regs_types.h>
#include <asm/mmu_fault.h>
#include <asm/kvm/mmu_hv_regs_types.h>

/*
 * VCPU state structure contains CPU, MMU, Local APIC and other registers
 * current values of VCPU. The structure is common for host and guest and
 * can (and should) be accessed by both.
 * See for more details arch/e2k/kvm/cpu_defs.h
 */

/*
 * Basic functions to access to virtual MMUs registers on host.
 */
static inline mmu_reg_t *
kvm_get_pv_vcpu_mmu_regs(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->mmu.regs;
}
static inline trap_cellar_t *
kvm_get_pv_vcpu_mmu_trap_cellar(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.kmap_vcpu_state->mmu.tcellar;
}

static inline mmu_reg_t
kvm_read_pv_mmu_reg(mmu_reg_t *mmu_regs, mmu_addr_t mmu_addr)
{
	int mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr_val(mmu_addr));

	return mmu_regs[mmu_reg_no];
}

static inline mmu_reg_t
kvm_read_pv_vcpu_mmu_reg(struct kvm_vcpu *vcpu, mmu_addr_t mmu_addr)
{
	mmu_reg_t *mmu_regs = kvm_get_pv_vcpu_mmu_regs(vcpu);

	return kvm_read_pv_mmu_reg(mmu_regs, mmu_addr);
}

static inline void
kvm_write_pv_mmu_reg(mmu_reg_t *mmu_regs,
			mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	int mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr_val(mmu_addr));

	mmu_regs[mmu_reg_no] = mmu_reg_val(mmu_reg);
}

static inline void
kvm_write_pv_vcpu_mmu_reg(struct kvm_vcpu *vcpu,
				mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	mmu_reg_t *mmu_regs = kvm_get_pv_vcpu_mmu_regs(vcpu);

	kvm_write_pv_mmu_reg(mmu_regs, mmu_addr, mmu_reg);
}

static inline unsigned int
kvm_read_pv_mmu_TRAP_COUNT_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_TRAP_COUNT);
}
static inline unsigned int
kvm_read_pv_vcpu_mmu_TRAP_COUNT_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_TRAP_COUNT);
}
static inline void
kvm_write_pv_mmu_TRAP_COUNT_reg(mmu_reg_t *mmu_regs, unsigned int count)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_TRAP_COUNT, __mmu_reg(count));
}
static inline void
kvm_write_pv_vcpu_mmu_TRAP_COUNT_reg(struct kvm_vcpu *vcpu, unsigned int count)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_TRAP_COUNT, __mmu_reg(count));
}

static inline mmu_reg_t
kvm_read_pv_MMU_CR_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_CR);
}
static inline mmu_reg_t
kvm_read_pv_vcpu_MMU_CR_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_CR);
}
static inline void
kvm_write_pv_MMU_CR_reg(mmu_reg_t *mmu_regs, mmu_reg_t mmu_cr)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_CR, mmu_cr);
}
static inline void
kvm_write_pv_vcpu_MMU_CR_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t mmu_cr)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_CR, AW(mmu_cr));
}

static inline unsigned int
kvm_read_pv_mmu_PID_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_PID);
}
static inline unsigned int
kvm_read_pv_vcpu_mmu_PID_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_PID);
}
static inline void
kvm_write_pv_mmu_PID_reg(mmu_reg_t *mmu_regs, unsigned int pid)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_PID, MMU_PID(pid));
}
static inline void
kvm_write_pv_vcpu_mmu_PID_reg(struct kvm_vcpu *vcpu, unsigned int pid)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_PID, MMU_PID(pid));
}

static inline e2k_addr_t
kvm_read_pv_mmu_OS_PPTB_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_PPTB);
}
static inline e2k_addr_t
kvm_read_pv_vcpu_mmu_OS_PPTB_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_PPTB);
}
static inline void
kvm_write_pv_mmu_OS_PPTB_reg(mmu_reg_t *mmu_regs, e2k_addr_t phys_pgd)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_PPTB,
						MMU_ADDR_TO_PPTB(phys_pgd));
}
static inline void
kvm_write_pv_vcpu_mmu_OS_PPTB_reg(struct kvm_vcpu *vcpu, e2k_addr_t phys_pgd)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_PPTB,
						MMU_ADDR_TO_PPTB(phys_pgd));
}

static inline e2k_addr_t
kvm_read_pv_mmu_OS_VPTB_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_VPTB);
}
static inline e2k_addr_t
kvm_read_pv_vcpu_mmu_OS_VPTB_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_VPTB);
}
static inline void
kvm_write_pv_mmu_OS_VPTB_reg(mmu_reg_t *mmu_regs, e2k_addr_t virt_addr)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_VPTB,
						MMU_ADDR_TO_VPTB(virt_addr));
}
static inline void
kvm_write_pv_vcpu_mmu_OS_VPTB_reg(struct kvm_vcpu *vcpu, e2k_addr_t virt_addr)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_VPTB,
						MMU_ADDR_TO_VPTB(virt_addr));
}

static inline e2k_addr_t
kvm_read_pv_mmu_U_PPTB_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_U_PPTB);
}
static inline e2k_addr_t
kvm_read_pv_vcpu_mmu_U_PPTB_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_U_PPTB);
}
static inline void
kvm_write_pv_mmu_U_PPTB_reg(mmu_reg_t *mmu_regs, e2k_addr_t phys_pgd)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_U_PPTB,
						MMU_ADDR_TO_PPTB(phys_pgd));
}
static inline void
kvm_write_pv_vcpu_mmu_U_PPTB_reg(struct kvm_vcpu *vcpu, e2k_addr_t phys_pgd)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_U_PPTB,
						MMU_ADDR_TO_PPTB(phys_pgd));
}

static inline e2k_addr_t
kvm_read_pv_mmu_U_VPTB_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_U_VPTB);
}
static inline e2k_addr_t
kvm_read_pv_vcpu_mmu_U_VPTB_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_U_VPTB);
}
static inline void
kvm_write_pv_mmu_U_VPTB_reg(mmu_reg_t *mmu_regs, e2k_addr_t virt_addr)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_U_VPTB,
						MMU_ADDR_TO_VPTB(virt_addr));
}
static inline void
kvm_write_pv_vcpu_mmu_U_VPTB_reg(struct kvm_vcpu *vcpu, e2k_addr_t virt_addr)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_U_VPTB,
						MMU_ADDR_TO_VPTB(virt_addr));
}

static inline e2k_addr_t
kvm_read_pv_mmu_OS_VAB_reg(mmu_reg_t *mmu_regs)
{
	return kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_VAB);
}
static inline e2k_addr_t
kvm_read_pv_vcpu_mmu_OS_VAB_reg(struct kvm_vcpu *vcpu)
{
	return kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_VAB);
}
static inline void
kvm_write_pv_mmu_OS_VAB_reg(mmu_reg_t *mmu_regs, e2k_addr_t virt_addr)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_OS_VPTB,
						MMU_ADDR_TO_VAB(virt_addr));
}
static inline void
kvm_write_pv_vcpu_mmu_OS_VAB_reg(struct kvm_vcpu *vcpu, e2k_addr_t virt_addr)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_OS_VPTB,
						MMU_ADDR_TO_VAB(virt_addr));
}

static inline bool
kvm_read_pv_mmu_US_CL_D_reg(mmu_reg_t *mmu_regs)
{
	return (bool)kvm_read_pv_mmu_reg(mmu_regs, MMU_ADDR_US_CL_D);
}
static inline bool
kvm_read_pv_vcpu_mmu_US_CL_D_reg(struct kvm_vcpu *vcpu)
{
	return (bool)kvm_read_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_US_CL_D);
}
static inline void
kvm_write_pv_mmu_US_CL_D_reg(mmu_reg_t *mmu_regs, bool disable)
{
	kvm_write_pv_mmu_reg(mmu_regs, MMU_ADDR_US_CL_D, __mmu_reg(disable));
}
static inline void
kvm_write_pv_vcpu_mmu_US_CL_D_reg(struct kvm_vcpu *vcpu, bool disable)
{
	kvm_write_pv_vcpu_mmu_reg(vcpu, MMU_ADDR_US_CL_D, __mmu_reg(disable));
}

static inline void
kvm_read_pv_mmu_tc_entry(trap_cellar_t *tc, int tc_no, trap_cellar_t *tc_entry)
{
	trap_cellar_t *tcellar;

	BUG_ON(tc_no * 3 > MAX_TC_SIZE);
	tcellar = &tc[tc_no];
	tc_entry->address = tcellar->address;
	tc_entry->condition = tcellar->condition;
	if (AS(tcellar->condition).store) {
		native_move_tagged_dword((e2k_addr_t)&tcellar->data,
						(e2k_addr_t)&tc_entry->data);
	}
}
static inline void
kvm_read_pv_vcpu_mmu_tc_entry(struct kvm_vcpu *vcpu,
				int tc_no, trap_cellar_t *tc_entry)
{
	trap_cellar_t *tc = kvm_get_pv_vcpu_mmu_trap_cellar(vcpu);

	kvm_read_pv_mmu_tc_entry(tc, tc_no, tc_entry);
}

static inline void
kvm_write_pv_mmu_tc_entry(trap_cellar_t *tc, int tc_no,
		e2k_addr_t address, tc_cond_t condition, u64 *data)
{
	trap_cellar_t *tcellar;

	BUG_ON(tc_no * 3 > MAX_TC_SIZE);
	tcellar = &tc[tc_no];
	tcellar->address = address;
	tcellar->condition = condition;
	if (data != NULL) {
		native_move_tagged_dword((e2k_addr_t)data,
						(e2k_addr_t)&tcellar->data);
	}
}

static inline void
kvm_write_pv_vcpu_mmu_tc_entry(struct kvm_vcpu *vcpu, int tc_no,
		e2k_addr_t address, tc_cond_t condition, u64 *data)
{
	trap_cellar_t *tc = kvm_get_pv_vcpu_mmu_trap_cellar(vcpu);

	kvm_write_pv_mmu_tc_entry(tc, tc_no, address, condition, data);
}

#endif	/* __KVM_E2K_MMU_DEFS_H */
