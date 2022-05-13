/*
 * E2K MMU virtualization extensions registers access
 *
 * Copyright 2018 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_MMU_HV_REGS_ACCESS_H_
#define	_E2K_KVM_MMU_HV_REGS_ACCESS_H_

#include <linux/types.h>
#include <linux/kvm_host.h>
#include <asm/e2k_api.h>
#include <asm/machdep.h>

#include <asm/mmu_regs_types.h>
#include <asm/mmu_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>

/*
 * MMU registers operations
 */

#ifndef __ASSEMBLY__

#define	READ_VIRT_CTRL_MU_REG() \
	((virt_ctrl_mu_t) { .word = NATIVE_GET_MMUREG(virt_ctrl_mu) })
#define	WRITE_VIRT_CTRL_MU_REG_VALUE(v) NATIVE_SET_MMUREG(virt_ctrl_mu, (v))
#define	WRITE_VIRT_CTRL_MU_REG(v) \
	NATIVE_SET_MMUREG(virt_ctrl_mu, ((virt_ctrl_mu_t) (v)).word)

#define	READ_G_W_IMASK_MMU_CR_REG_VALUE()	\
		NATIVE_GET_MMUREG(g_w_imask_mmu_cr)
#define	WRITE_G_W_IMASK_MMU_CR_REG_VALUE(val)	\
		NATIVE_SET_MMUREG(g_w_imask_mmu_cr, (val))

#define	READ_GID_REG_VALUE()		NATIVE_GET_MMUREG(gid)
#define	WRITE_GID_REG_VALUE(val)	NATIVE_SET_MMUREG(gid, (val))

#define	READ_GP_VPTB_REG_VALUE()	NATIVE_GET_MMUREG(gp_vptb)
#define	WRITE_GP_VPTB_REG_VALUE(val)	NATIVE_SET_MMUREG(gp_vptb, (val))

#define	READ_GP_PPTB_REG_VALUE()	NATIVE_GET_MMUREG(gp_pptb)
#define	WRITE_GP_PPTB_REG_VALUE(val)	NATIVE_SET_MMUREG(gp_pptb, (val))

#define	READ_INTC_INFO_MU()		NATIVE_GET_MMUREG(intc_info_mu)
#define	WRITE_INTC_INFO_MU(x)		NATIVE_SET_MMUREG(intc_info_mu, (x))

#define	READ_INTC_PTR_MU()	NATIVE_GET_MMUREG(intc_ptr_mu)

static inline void __save_intc_info_mu(intc_info_mu_t *info, int *num)
{
	long info_ptr, i = 0;

	/*
	 * The read of INTC_PTR will clear the hardware pointer,
	 * but the subsequent reads for INTC_INFO will increase
	 * it again until it reaches the same value it had before.
	 */
	info_ptr = READ_INTC_PTR_MU();
	if (!info_ptr) {
		*num = -1;
		return;
	}
	if (info_ptr % INTC_INFO_MU_ITEM_SIZE != 0) {
		KVM_WARN_ON(true);
		info_ptr = ((info_ptr + (INTC_INFO_MU_ITEM_SIZE - 1)) /
					INTC_INFO_MU_ITEM_SIZE) *
						INTC_INFO_MU_ITEM_SIZE;
	}

	do {
		info[i].no_restore = false;
		info[i].modify_data = false;
		info[i].hdr = (intc_info_mu_hdr_t) READ_INTC_INFO_MU();
		info[i].gpa = (u64) READ_INTC_INFO_MU();
		info[i].gva = (u64) READ_INTC_INFO_MU();
		NATIVE_STORE_TAGGED_MMUREG(&info[i].data, intc_info_mu);
		info[i].condition = (tc_cond_t) READ_INTC_INFO_MU();
		NATIVE_STORE_TAGGED_MMUREG(&info[i].data_ext, intc_info_mu);
		info[i].mask = (tc_mask_t) READ_INTC_INFO_MU();
		++i;
		info_ptr -= INTC_INFO_MU_ITEM_SIZE;
	} while (info_ptr > 0);

	*num = i;
}

#define fixup_intc_info_mu(info, num) \
do { \
	int entries = *num; \
	if (entries > 0 && cpu_has(CPU_HWBUG_GUEST_ASYNC_PM)) { \
		e2k_mem_crs_t *frame; \
		e2k_pcsp_lo_t bu_pcsp_lo; \
		e2k_pcsp_hi_t bu_pcsp_hi; \
 \
		AW(bu_pcsp_lo) = READ_BU_PCSP_LO_REG_VALUE(); \
		AW(bu_pcsp_hi) = READ_BU_PCSP_HI_REG_VALUE(); \
		frame = (e2k_mem_crs_t *) (AS(bu_pcsp_lo).base + \
					   AS(bu_pcsp_hi).ind); \
		--frame; \
		if (!AS(frame->cr1_lo).pm) { \
			int entry; \
			for (entry = 0; entry < entries; entry++) { \
				/* Protected mode accesses are always \
				 * privileged, so keep "pm" for them. */ \
				if (AS(info[entry].condition).npsp) \
					AS(info[entry].condition).pm = 0; \
			} \
		} \
	} \
} while (0)

/* Use macro magic to escape header hell */
#define save_intc_info_mu(info, num) \
do { \
	__save_intc_info_mu(info, num); \
	fixup_intc_info_mu(info, num); \
} while (0)


static inline void
restore_intc_info_mu(const intc_info_mu_t *info, int num)
{
	int i;

	/*
	 * 1) Clear the hardware pointer
	 */
	READ_INTC_PTR_MU();
	if (num == -1)
		return;

	/*
	 * 2) Write the registers
	 */
	for (i = 0; i < num; i++) {
		if (!info[i].no_restore) {
			WRITE_INTC_INFO_MU(AW(info[i].hdr));
			WRITE_INTC_INFO_MU(info[i].gpa);
			WRITE_INTC_INFO_MU(info[i].gva);
			NATIVE_TAGGED_LOAD_TO_MMUREG(intc_info_mu,
					&info[i].data);
			WRITE_INTC_INFO_MU(AW(info[i].condition));
			NATIVE_TAGGED_LOAD_TO_MMUREG(intc_info_mu,
					&info[i].data_ext);
			WRITE_INTC_INFO_MU(AW(info[i].mask));
		}
	}
}

static inline void
modify_intc_info_mu_data(intc_info_mu_t *info, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (unlikely(info[i].modify_data)) {
			info[i].data = info[i].mod_data;
			info[i].data_ext = info[i].mod_data_ext;
		}
	}
}

static inline void
kvm_set_intc_info_mu_modified_data(intc_info_mu_t *info, unsigned long data,
	unsigned long data_ext)
{
	info->mod_data = data;
	info->mod_data_ext = data_ext;
	info->modify_data = true;
}
static inline void
kvm_reset_intc_info_mu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.mu_updated = false;
}
static inline void
kvm_set_intc_info_mu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.mu_updated = true;
}
static inline bool
kvm_get_intc_info_mu_is_updated(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.intc_ctxt.mu_updated;
}

#define	READ_SH_OS_PPTB_REG_VALUE()	NATIVE_GET_MMUREG(sh_os_pptb)
#define	WRITE_SH_OS_PPTB_REG_VALUE(val)	NATIVE_SET_MMUREG(sh_os_pptb, (val))

#define	READ_SH_OS_VPTB_REG_VALUE()	NATIVE_GET_MMUREG(sh_os_vptb)
#define	WRITE_SH_OS_VPTB_REG_VALUE(val)	NATIVE_SET_MMUREG(sh_os_vptb, (val))

#define	READ_SH_OS_VAB_REG_VALUE()	NATIVE_GET_MMUREG(sh_os_vab)
#define	WRITE_SH_OS_VAB_REG_VALUE(val)	NATIVE_SET_MMUREG(sh_os_vab, (val))

#define	READ_SH_PID_REG_VALUE()		NATIVE_GET_MMUREG(sh_pid)
#define	WRITE_SH_PID_REG_VALUE(val)	NATIVE_SET_MMUREG(sh_pid, (val))

#define	READ_CR_G_W_IMASK_REG_VALUE()	NATIVE_GET_MMUREG(g_w_imask_mmu_cr)
#define	WRITE_CR_G_W_IMASK_REG_VALUE(val) \
		NATIVE_SET_MMUREG(g_w_imask_mmu_cr, (val))

#define	READ_SH_MMU_CR_REG_VALUE()	NATIVE_GET_MMUREG(sh_mmu_cr)
#define	WRITE_SH_MMU_CR_REG_VALUE(val)	NATIVE_SET_MMUREG(sh_mmu_cr, (val))

#ifdef CONFIG_VIRTUALIZATION
static inline virt_ctrl_mu_t read_VIRT_CTRL_MU_reg(void)
{
	virt_ctrl_mu_t virt_ctrl;

	virt_ctrl.VIRT_CTRL_MU_reg = machine.host.read_VIRT_CTRL_MU();
	return virt_ctrl;
}
static inline void write_VIRT_CTRL_MU_reg(virt_ctrl_mu_t virt_ctrl)
{
	machine.host.write_VIRT_CTRL_MU(virt_ctrl.VIRT_CTRL_MU_reg);
}

static inline unsigned int read_GID_reg(void)
{
	return machine.host.read_GID();
}
static inline void write_GID_reg(unsigned int mmu_gid)
{
	machine.host.write_GID(MMU_GID(mmu_gid));
}

static inline e2k_mmu_cr_t read_SH_MMU_CR_reg(void)
{
	return (e2k_mmu_cr_t) { .word = machine.host.read_SH_MMU_CR() };
}
static inline void write_SH_MMU_CR_reg(e2k_mmu_cr_t mmu_cr)
{
	machine.host.write_SH_MMU_CR(AW(mmu_cr));
}

static inline e2k_mmu_cr_t read_G_W_IMASK_MMU_CR_reg(void)
{
	return (e2k_mmu_cr_t) { .word = machine.host.read_G_W_IMASK_MMU_CR() };
}
static inline void write_G_W_IMASK_MMU_CR_reg(e2k_mmu_cr_t mmu_cr_mask)
{
	machine.host.write_G_W_IMASK_MMU_CR(AW(mmu_cr_mask));
}

static inline unsigned int read_SH_PID_reg(void)
{
	return machine.host.read_SH_PID();
}
static inline void write_SH_PID_reg(unsigned int mmu_pid)
{
	machine.host.write_SH_PID(MMU_PID(mmu_pid));
}

static inline e2k_addr_t read_SH_OS_PPTB_reg(void)
{
	return machine.host.read_SH_OS_PPTB();
}
static inline void write_SH_OS_PPTB_reg(e2k_addr_t phys_addr)
{
	machine.host.write_SH_OS_PPTB(MMU_ADDR_TO_PPTB(phys_addr));
}

static inline e2k_addr_t read_SH_OS_VPTB_reg(void)
{
	return machine.host.read_SH_OS_VPTB();
}
static inline void write_SH_OS_VPTB_reg(e2k_addr_t virt_addr)
{
	machine.host.write_SH_OS_VPTB(MMU_ADDR_TO_VPTB(virt_addr));
}

static inline e2k_addr_t read_GP_PPTB_reg(void)
{
	return machine.host.read_GP_PPTB();
}
static inline void write_GP_PPTB_reg(e2k_addr_t phys_addr)
{
	machine.host.write_GP_PPTB(MMU_ADDR_TO_PPTB(phys_addr));
}

static inline e2k_addr_t read_GP_VPTB_reg(void)
{
	return machine.host.read_GP_VPTB();
}
static inline void write_GP_VPTB_reg(e2k_addr_t virt_addr)
{
	machine.host.write_GP_VPTB(MMU_ADDR_TO_VPTB(virt_addr));
}

static inline e2k_addr_t read_SH_OS_VAB_reg(void)
{
	return machine.host.read_SH_OS_VAB();
}
static inline void write_SH_OS_VAB_reg(e2k_addr_t virt_addr)
{
	machine.host.write_SH_OS_VAB(MMU_ADDR_TO_VAB(virt_addr));
}
#endif /* CONFIG_VIRTUALIZATION */
#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_KVM_MMU_HV_REGS_ACCESS_H_ */
