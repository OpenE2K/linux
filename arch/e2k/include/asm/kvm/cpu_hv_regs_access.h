#ifndef	_E2K_KVM_CPU_HV_REGS_ACCESS_H_
#define	_E2K_KVM_CPU_HV_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/kvm_host.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/machdep.h>

/*
 * Virtualization control registers
 */
#define	READ_VIRT_CTRL_CU_REG() \
	((virt_ctrl_cu_t) { .word = NATIVE_GET_DSREG_CLOSED(virt_ctrl_cu) })
/* Bug #127239: on some CPUs "rwd %virt_ctrl_cu" instruction must also
 * contain a NOP.  This is already accomplished by using delay "5" here. */
#define	WRITE_VIRT_CTRL_CU_REG(v) \
	NATIVE_SET_DSREG_CLOSED_NOEXC(virt_ctrl_cu, ((virt_ctrl_cu_t) (v)).word, 5)

/* Shadow CPU registers */

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (SH_OSCUD)
 */

#define	READ_SH_OSCUD_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_oscud.lo)
#define	READ_SH_OSCUD_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_oscud.hi)

#define	WRITE_SH_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_oscud.lo, OSCUD_lo_value, 5)
#define	WRITE_SH_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_oscud.hi, OSCUD_hi_value, 5)
#define	WRITE_SH_OSCUD_LO_REG(OSCUD_lo) \
({ \
	WRITE_SH_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	WRITE_SH_OSCUD_HI_REG(OSCUD_hi) \
({ \
	WRITE_SH_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	WRITE_SH_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	WRITE_SH_OSCUD_LO_REG_VALUE(OSCUD_hi_value); \
	WRITE_SH_OSCUD_HI_REG_VALUE(OSCUD_lo_value); \
})
#define	WRITE_SH_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	WRITE_SH_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, \
					OSCUD_lo.OSCUD_lo_half); \
})

/*
 * Read/write low/hgh double-word OS Globals Register (SH_OSGD)
 */

#define	READ_SH_OSGD_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_osgd.lo)
#define	READ_SH_OSGD_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_osgd.hi)

#define	WRITE_SH_OSGD_LO_REG_VALUE(OSGD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_osgd.lo, OSGD_lo_value, 5)
#define	WRITE_SH_OSGD_HI_REG_VALUE(OSGD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_osgd.hi, OSGD_hi_value, 5)
#define	WRITE_SH_OSGD_LO_REG(OSGD_lo) \
({ \
	WRITE_SH_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	WRITE_SH_OSGD_HI_REG(OSGD_hi) \
({ \
	WRITE_SH_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	WRITE_SH_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
({ \
	WRITE_SH_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	WRITE_SH_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define	WRITE_SH_OSGD_REG(OSGD_hi, OSGD_lo) \
({ \
	WRITE_SH_OSGD_REG_VALUE(OSGD_hi.OSGD_hi_half, \
					OSGD_lo.OSGD_lo_half); \
})

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register
 * (SH_PSP, backup BU_PSP)
 */

#define	READ_SH_PSP_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_psp.lo)
#define	READ_SH_PSP_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_psp.hi)
#define	READ_BU_PSP_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(bu_psp.lo)
#define	READ_BU_PSP_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(bu_psp.hi)

#define	WRITE_SH_PSP_LO_REG_VALUE(PSP_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_psp.lo, PSP_lo_value, 5)
#define	WRITE_SH_PSP_HI_REG_VALUE(PSP_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_psp.hi, PSP_hi_value, 5)
#define	WRITE_BU_PSP_LO_REG_VALUE(PSP_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(bu_psp.lo, PSP_lo_value, 5)
#define	WRITE_BU_PSP_HI_REG_VALUE(PSP_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(bu_psp.hi, PSP_hi_value, 5)

/*
 * Read/write word Procedure Stack Harware Top Pointer (SH_PSHTP)
 */
#define	READ_SH_PSHTP_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_pshtp)
#define	WRITE_SH_PSHTP_REG_VALUE(PSHTP_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_pshtp, PSHTP_value, 5)

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register
 * (SH_PCSP, backup registers BU_PCSP)
 */
#define	READ_SH_PCSP_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_pcsp.lo)
#define	READ_SH_PCSP_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_pcsp.hi)
#define	READ_BU_PCSP_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(bu_pcsp.lo)
#define	READ_BU_PCSP_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(bu_pcsp.hi)

#define	WRITE_SH_PCSP_LO_REG_VALUE(PCSP_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_pcsp.lo, PCSP_lo_value, 5)
#define	WRITE_SH_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_pcsp.hi, PCSP_hi_value, 5)
#define	WRITE_BU_PCSP_LO_REG_VALUE(PCSP_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(bu_pcsp.lo, PCSP_lo_value, 5)
#define	WRITE_BU_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(bu_pcsp.hi, PCSP_hi_value, 5)

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (SH_PCSHTP)
 * and shadow pointer (SH_PCSHTP)
 */
#define	READ_SH_PCSHTP_REG_VALUE()			\
		NATIVE_GET_SREG_CLOSED(sh_pcshtp)
#define	READ_SH_PCSHTP_REG_SVALUE()			\
		PCSHTP_SIGN_EXTEND(NATIVE_GET_SREG_CLOSED(sh_pcshtp))
#define	WRITE_SH_PCSHTP_REG_SVALUE(PCSHTP_svalue)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(sh_pcshtp, PCSHTP_svalue, 5)

/*
 * Read/write current window descriptor register (SH_WD)
 */
#define	READ_SH_WD_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_wd)
#define	WRITE_SH_WD_REG_VALUE(WD_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_wd, WD_value, 5)

/*
 * Read/write OS register which point to current process thread info
 * structure (SH_OSR0)
 */
#define	READ_SH_OSR0_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_osr0)

#define	WRITE_SH_OSR0_REG_VALUE(osr0_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_osr0, osr0_value, 5)

/*
 * Read/Write system clock registers (SH_SCLKM3)
 */
#define	READ_SH_SCLKM3_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_sclkm3)

#define	WRITE_SH_SCLKM3_REG_VALUE(reg_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_sclkm3, reg_value, 4)

/*
 * Read/write double-word Compilation Unit Table Register (SH_OSCUTD)
 */
#define	READ_SH_OSCUTD_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sh_oscutd)

#define	WRITE_SH_OSCUTD_REG_VALUE(CUTD_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_oscutd, CUTD_value, 7)
#define	WRITE_SH_OSCUTD_REG(value) WRITE_SH_OSCUTD_REG_VALUE(AW(value))

/*
 * Read/write word Compilation Unit Index Register (SH_OSCUIR)
 */
#define	READ_SH_OSCUIR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(sh_oscuir)

#define	WRITE_SH_OSCUIR_REG_VALUE(CUIR_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_oscuir, CUIR_value, 7)
#define	WRITE_SH_OSCUIR_REG(value) WRITE_SH_OSCUIR_REG_VALUE(AW(value))

/*
 * Read/Write Processor Core Mode Register (SH_CORE_MODE)
 */
#define	READ_SH_CORE_MODE_REG_VALUE()	NATIVE_GET_SREG_CLOSED(sh_core_mode)
#define	WRITE_SH_CORE_MODE_REG_VALUE(modes)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(sh_core_mode, modes, 5)

#ifdef CONFIG_VIRTUALIZATION
static inline e2k_core_mode_t read_SH_CORE_MODE_reg(void)
{
	e2k_core_mode_t core_mode;
	core_mode.CORE_MODE_reg = machine.host.read_SH_CORE_MODE();
	return core_mode;
}
static inline void write_SH_CORE_MODE_reg(e2k_core_mode_t core_mode)
{
	machine.host.write_SH_CORE_MODE(core_mode.CORE_MODE_reg);
}
#endif /* CONFIG_VIRTUALIZATION */

#define	READ_G_PREEMPT_TMR_REG() \
		((g_preempt_tmr_t) NATIVE_GET_DSREG_CLOSED(g_preempt_tmr))
#define	WRITE_G_PREEMPT_TMR_REG(x) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(g_preempt_tmr, AW(x), 5)

#define READ_INTC_PTR_CU() NATIVE_GET_DSREG_CLOSED(intc_ptr_cu)
#define READ_INTC_INFO_CU() NATIVE_GET_DSREG_CLOSED(intc_info_cu)
#define WRITE_INTC_INFO_CU(x) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(intc_info_cu, x, 5)

/* Clear INTC_INFO_CU header and INTC_PTR_CU */
static inline void clear_intc_info_cu(void)
{
	READ_INTC_PTR_CU();
	WRITE_INTC_INFO_CU(0ULL);
	WRITE_INTC_INFO_CU(0ULL);
	READ_INTC_PTR_CU();
}

static inline void save_intc_info_cu(intc_info_cu_t *info, int *num)
{
	u64 info_ptr, i = 0;

	/*
	 * The read of INTC_PTR will clear the hardware pointer,
	 * but the subsequent reads fo INTC_INFO will increase
	 * it again until it reaches the same value it had before.
	 */
	info_ptr = READ_INTC_PTR_CU();
	if (!info_ptr) {
		*num = -1;
		AW(info->header.lo) = 0;
		AW(info->header.hi) = 0;
		return;
	}

	AW(info->header.lo) = READ_INTC_INFO_CU();
	AW(info->header.hi) = READ_INTC_INFO_CU();
	info_ptr -= 2;

	/*
	 * Read intercepted events list
	 */
	for (; info_ptr > 0; info_ptr -= 2) {
		AW(info->entry[i].lo) = READ_INTC_INFO_CU();
		info->entry[i].hi = READ_INTC_INFO_CU();
		info->entry[i].no_restore = false;
		++i;
	};

	*num = i;
}

static inline void restore_intc_info_cu(const intc_info_cu_t *info, int num)
{
	int i;

	/* Clear the pointer, in case we just migrated to new cpu */
	READ_INTC_PTR_CU();

	/* Header will be cleared by hardware during GLAUNCH */
	if (num == -1 || num == 0)
		return;

	/*
	 * Restore intercepted events. Header flags aren't used for reexecution,
	 * so restore 0 in header.
	 */
	WRITE_INTC_INFO_CU(0ULL);
	WRITE_INTC_INFO_CU(0ULL);
	for (i = 0; i < num; i++) {
		if (!info->entry[i].no_restore) {
			WRITE_INTC_INFO_CU(AW(info->entry[i].lo));
			WRITE_INTC_INFO_CU(info->entry[i].hi);
		}
	}
}

static inline void
kvm_reset_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.cu_updated = false;
}
static inline void
kvm_set_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	vcpu->arch.intc_ctxt.cu_updated = true;
}
static inline bool
kvm_get_intc_info_cu_is_updated(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.intc_ctxt.cu_updated;
}

#endif	/*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_KVM_CPU_HV_REGS_ACCESS_H_ */
