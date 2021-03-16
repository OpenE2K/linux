#ifndef	_E2K_KVM_CPU_HV_REGS_ACCESS_H_
#define	_E2K_KVM_CPU_HV_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <linux/kvm_host.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/kvm/cpu_hv_regs_types.h>

/*
 * Virtualization control registers
 */
#define	READ_VIRT_CTRL_CU_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(virt_ctrl_cu)
/* Bug #127239: on some CPUs "rwd %virt_ctrl_cu" instruction must also
 * contain a NOP.  This is already accomplished by using delay "5" here. */
#define	WRITE_VIRT_CTRL_CU_REG_VALUE(virt_ctrl)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(virt_ctrl_cu, virt_ctrl, 5)
#define	READ_VIRT_CTRL_CU_REG()		read_VIRT_CTRL_CU_reg()
#define	WRITE_VIRT_CTRL_CU_REG(virt_ctrl)	\
		write_VIRT_CTRL_CU_reg(virt_ctrl)

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

/*
 * Read/write word Compilation Unit Index Register (SH_OSCUIR)
 */
#define	READ_SH_OSCUIR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(sh_oscuir)

#define	WRITE_SH_OSCUIR_REG_VALUE(CUIR_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sh_oscuir, CUIR_value, 7)

/*
 * Read/Write Processor Core Mode Register (SH_CORE_MODE)
 */
#define	READ_SH_CORE_MODE_REG_VALUE()	NATIVE_GET_SREG_CLOSED(sh_core_mode)
#define	WRITE_SH_CORE_MODE_REG_VALUE(modes)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(sh_core_mode, modes, 5)

extern unsigned long read_VIRT_CTRL_CU_reg_value(void);
extern void write_VIRT_CTRL_CU_reg_value(unsigned long value);
extern unsigned int read_SH_CORE_MODE_reg_value(void);
extern void write_SH_CORE_MODE_reg_value(unsigned int value);
extern unsigned long read_SH_PSP_LO_reg_value(void);
extern unsigned long read_SH_PSP_HI_reg_value(void);
extern void write_SH_PSP_LO_reg_value(unsigned long value);
extern void write_SH_PSP_HI_reg_value(unsigned long value);
extern unsigned long read_BU_PSP_LO_reg_value(void);
extern unsigned long read_BU_PSP_HI_reg_value(void);
extern void write_BU_PSP_LO_reg_value(unsigned long value);
extern void write_BU_PSP_HI_reg_value(unsigned long value);
extern unsigned long read_SH_PSHTP_reg_value(void);
extern void write_SH_PSHTP_reg_value(unsigned long value);
extern unsigned long read_SH_PCSP_LO_reg_value(void);
extern unsigned long read_SH_PCSP_HI_reg_value(void);
extern void write_SH_PCSP_LO_reg_value(unsigned long value);
extern void write_SH_PCSP_HI_reg_value(unsigned long value);
extern unsigned long read_BU_PCSP_LO_reg_value(void);
extern unsigned long read_BU_PCSP_HI_reg_value(void);
extern void write_BU_PCSP_LO_reg_value(unsigned long value);
extern void write_BU_PCSP_HI_reg_value(unsigned long value);
extern int read_SH_PCSHTP_reg_value(void);
extern void write_SH_PCSHTP_reg_value(int value);
extern unsigned long read_SH_WD_reg_value(void);
extern void write_SH_WD_reg_value(unsigned long value);
extern unsigned long read_SH_OSCUD_LO_reg_value(void);
extern unsigned long read_SH_OSCUD_HI_reg_value(void);
extern void write_SH_OSCUD_LO_reg_value(unsigned long value);
extern void write_SH_OSCUD_HI_reg_value(unsigned long value);
extern unsigned long read_SH_OSGD_LO_reg_value(void);
extern unsigned long read_SH_OSGD_HI_reg_value(void);
extern void write_SH_OSGD_LO_reg_value(unsigned long value);
extern void write_SH_OSGD_HI_reg_value(unsigned long value);
extern unsigned long read_SH_OSCUTD_reg_value(void);
extern void write_SH_OSCUTD_reg_value(unsigned long value);
extern unsigned int read_SH_OSCUIR_reg_value(void);
extern void write_SH_OSCUIR_reg_value(unsigned int value);
extern unsigned long read_SH_OSR0_reg_value(void);
extern void write_SH_OSR0_reg_value(unsigned long value);

static inline virt_ctrl_cu_t read_VIRT_CTRL_CU_reg(void)
{
	virt_ctrl_cu_t virt_ctrl;

	virt_ctrl.VIRT_CTRL_CU_reg = read_VIRT_CTRL_CU_reg_value();
	return virt_ctrl;
}
static inline void write_VIRT_CTRL_CU_reg(virt_ctrl_cu_t virt_ctrl)
{
	write_VIRT_CTRL_CU_reg_value(virt_ctrl.VIRT_CTRL_CU_reg);
}

static inline e2k_psp_lo_t read_SH_PSP_LO_reg(void)
{
	e2k_psp_lo_t psp_lo;

	psp_lo.PSP_lo_half = read_SH_PSP_LO_reg_value();
	return psp_lo;
}
static inline e2k_psp_hi_t read_SH_PSP_HI_reg(void)
{
	e2k_psp_hi_t psp_hi;

	psp_hi.PSP_hi_half = read_SH_PSP_HI_reg_value();
	return psp_hi;
}
static inline void write_SH_PSP_LO_reg(e2k_psp_lo_t psp_lo)
{
	write_SH_PSP_LO_reg_value(psp_lo.PSP_lo_half);
}
static inline void write_SH_PSP_HI_reg(e2k_psp_hi_t psp_hi)
{
	write_SH_PSP_HI_reg_value(psp_hi.PSP_hi_half);
}

static inline e2k_pcsp_lo_t read_SH_PCSP_LO_reg(void)
{
	e2k_pcsp_lo_t pcsp_lo;

	pcsp_lo.PCSP_lo_half = read_SH_PCSP_LO_reg_value();
	return pcsp_lo;
}
static inline e2k_pcsp_hi_t read_SH_PCSP_HI_reg(void)
{
	e2k_pcsp_hi_t pcsp_hi;

	pcsp_hi.PCSP_hi_half = read_SH_PCSP_HI_reg_value();
	return pcsp_hi;
}
static inline void write_SH_PCSP_LO_reg(e2k_pcsp_lo_t pcsp_lo)
{
	write_SH_PCSP_LO_reg_value(pcsp_lo.PCSP_lo_half);
}
static inline void write_SH_PCSP_HI_reg(e2k_pcsp_hi_t pcsp_hi)
{
	write_SH_PCSP_HI_reg_value(pcsp_hi.PCSP_hi_half);
}

static inline e2k_psp_lo_t read_BU_PSP_LO_reg(void)
{
	e2k_psp_lo_t psp_lo;

	psp_lo.PSP_lo_half = read_BU_PSP_LO_reg_value();
	return psp_lo;
}
static inline e2k_psp_hi_t read_BU_PSP_HI_reg(void)
{
	e2k_psp_hi_t psp_hi;

	psp_hi.PSP_hi_half = read_BU_PSP_HI_reg_value();
	return psp_hi;
}
static inline void write_BU_PSP_LO_reg(e2k_psp_lo_t psp_lo)
{
	write_BU_PSP_LO_reg_value(psp_lo.PSP_lo_half);
}
static inline void write_BU_PSP_HI_reg(e2k_psp_hi_t psp_hi)
{
	write_BU_PSP_HI_reg_value(psp_hi.PSP_hi_half);
}

static inline e2k_pcsp_lo_t read_BU_PCSP_LO_reg(void)
{
	e2k_pcsp_lo_t pcsp_lo;

	pcsp_lo.PCSP_lo_half = read_BU_PCSP_LO_reg_value();
	return pcsp_lo;
}
static inline e2k_pcsp_hi_t read_BU_PCSP_HI_reg(void)
{
	e2k_pcsp_hi_t pcsp_hi;

	pcsp_hi.PCSP_hi_half = read_BU_PCSP_HI_reg_value();
	return pcsp_hi;
}
static inline void write_BU_PCSP_LO_reg(e2k_pcsp_lo_t pcsp_lo)
{
	write_BU_PCSP_LO_reg_value(pcsp_lo.PCSP_lo_half);
}
static inline void write_BU_PCSP_HI_reg(e2k_pcsp_hi_t pcsp_hi)
{
	write_BU_PCSP_HI_reg_value(pcsp_hi.PCSP_hi_half);
}

static inline e2k_oscud_lo_t read_SH_OSCUD_LO_reg(void)
{
	e2k_oscud_lo_t oscud_lo;

	oscud_lo.OSCUD_lo_half = read_SH_OSCUD_LO_reg_value();
	return oscud_lo;
}
static inline e2k_oscud_hi_t read_SH_OSCUD_HI_reg(void)
{
	e2k_oscud_hi_t oscud_hi;

	oscud_hi.OSCUD_hi_half = read_SH_OSCUD_HI_reg_value();
	return oscud_hi;
}
static inline void write_SH_OSCUD_LO_reg(e2k_oscud_lo_t oscud_lo)
{
	write_SH_OSCUD_LO_reg_value(oscud_lo.OSCUD_lo_half);
}
static inline void write_SH_OSCUD_HI_reg(e2k_oscud_hi_t oscud_hi)
{
	write_SH_OSCUD_HI_reg_value(oscud_hi.OSCUD_hi_half);
}

static inline e2k_osgd_lo_t read_SH_OSGD_LO_reg(void)
{
	e2k_osgd_lo_t osgd_lo;

	osgd_lo.OSGD_lo_half = read_SH_OSGD_LO_reg_value();
	return osgd_lo;
}
static inline e2k_osgd_hi_t read_SH_OSGD_HI_reg(void)
{
	e2k_osgd_hi_t osgd_hi;

	osgd_hi.OSGD_hi_half = read_SH_OSGD_HI_reg_value();
	return osgd_hi;
}
static inline void write_SH_OSGD_LO_reg(e2k_osgd_lo_t osgd_lo)
{
	write_SH_OSGD_LO_reg_value(osgd_lo.OSGD_lo_half);
}
static inline void write_SH_OSGD_HI_reg(e2k_osgd_hi_t osgd_hi)
{
	write_SH_OSGD_HI_reg_value(osgd_hi.OSGD_hi_half);
}

static inline e2k_cutd_t read_SH_OSCUTD_reg(void)
{
	e2k_cutd_t cutd;

	cutd.CUTD_reg = read_SH_OSCUTD_reg_value();
	return cutd;
}
static inline void write_SH_OSCUTD_reg(e2k_cutd_t cutd)
{
	write_SH_OSCUTD_reg_value(cutd.CUTD_reg);
}

static inline e2k_cuir_t read_SH_OSCUIR_reg(void)
{
	e2k_cuir_t cuir;

	cuir.CUIR_reg = read_SH_OSCUIR_reg_value();
	return cuir;
}
static inline void write_SH_OSCUIR_reg(e2k_cuir_t cuir)
{
	write_SH_OSCUIR_reg_value(cuir.CUIR_reg);
}

static inline e2k_core_mode_t read_SH_CORE_MODE_reg(void)
{
	e2k_core_mode_t core_mode;

	core_mode.CORE_MODE_reg = read_SH_CORE_MODE_reg_value();
	return core_mode;
}
static inline void write_SH_CORE_MODE_reg(e2k_core_mode_t core_mode)
{
	write_SH_CORE_MODE_reg_value(core_mode.CORE_MODE_reg);
}

#define	READ_G_PREEMPT_TMR_REG() \
		((e2k_g_preempt_tmr_t) NATIVE_GET_SREG_CLOSED(g_preempt_tmr))
#define	WRITE_G_PREEMPT_TMR_REG(x) \
		NATIVE_SET_SREG_CLOSED_NOEXC(g_preempt_tmr, AW(x), 5)

#define READ_INTC_PTR_CU() NATIVE_GET_DSREG_CLOSED(intc_ptr_cu)
#define READ_INTC_INFO_CU() NATIVE_GET_DSREG_CLOSED(intc_info_cu)
#define WRITE_INTC_INFO_CU(x) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(intc_info_cu, x, 5)

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

	/*
	 * CU header should be cleared --- fg@mcst.ru
	 */
	AW(info->header.lo) = READ_INTC_INFO_CU();
	AW(info->header.hi) = READ_INTC_INFO_CU();
	READ_INTC_PTR_CU();
	WRITE_INTC_INFO_CU(0ULL);
	WRITE_INTC_INFO_CU(0ULL);
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

	/*
	 * 1) Clear the hardware pointer
	 */
	READ_INTC_PTR_CU();
	if (num == -1)
		return;

	/*
	 * 2) Write the registers
	 *
	 * CU header should be cleared --- fg@mcst.ru
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
