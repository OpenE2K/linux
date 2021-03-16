
#ifndef	_E2K_NATIVE_CPU_REGS_ACCESS_H_
#define	_E2K_NATIVE_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

#define	NATIVE_READ_OSCUD_LO_REG_VALUE() NATIVE_GET_DSREG_CLOSED(oscud.lo)
#define	NATIVE_READ_OSCUD_HI_REG_VALUE() NATIVE_GET_DSREG_CLOSED(oscud.hi)

#define	NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(oscud.lo, OSCUD_lo_value, 5)
#define	NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(oscud.hi, OSCUD_hi_value, 5)
#define	NATIVE_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	NATIVE_NV_NOIRQ_WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	NATIVE_WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define	NATIVE_WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	NATIVE_WRITE_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, \
					OSCUD_lo.OSCUD_lo_half); \
})

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	NATIVE_READ_OSGD_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(osgd.lo)
#define	NATIVE_READ_OSGD_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(osgd.hi)

#define	NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(osgd.lo, OSGD_lo_value, 5)
#define	NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(osgd.hi, OSGD_hi_value, 5)
#define	NATIVE_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	NATIVE_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	NATIVE_WRITE_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
({ \
	NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define	NATIVE_WRITE_OSGD_REG(OSGD_hi, OSGD_lo) \
({ \
	NATIVE_WRITE_OSGD_REG_VALUE(OSGD_hi.OSGD_hi_half, \
					OSGD_lo.OSGD_lo_half); \
})

/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */

#define	NATIVE_READ_CUD_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(cud.lo)
#define	NATIVE_READ_CUD_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(cud.hi)

#define	NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(cud.lo, CUD_lo_value, 4)
#define	NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(cud.hi, CUD_hi_value, 4)
#define	NATIVE_WRITE_CUD_LO_REG(CUD_lo) \
({ \
	NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo.CUD_lo_half); \
})
#define	NATIVE_WRITE_CUD_HI_REG(CUD_hi) \
({ \
	NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi.CUD_hi_half); \
})
#define	NATIVE_WRITE_CUD_REG_VALUE(CUD_hi_value, CUD_lo_value) \
({ \
	NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
	NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define	NATIVE_WRITE_CUD_REG(CUD_hi, CUD_lo) \
({ \
	NATIVE_WRITE_CUD_REG_VALUE(CUD_hi.CUD_hi_half, CUD_lo.CUD_lo_half); \
})

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define	NATIVE_READ_GD_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(gd.lo)
#define	NATIVE_READ_GD_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(gd.hi)

#define	NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(gd.lo, GD_lo_value, 4)
#define	NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(gd.hi, GD_hi_value, 4)
#define	NATIVE_WRITE_GD_LO_REG(GD_lo)	\
		NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo.GD_lo_half)
#define	NATIVE_WRITE_GD_HI_REG(GD_hi)	\
		NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi.GD_hi_half)
#define	NATIVE_WRITE_GD_REG_VALUE(GD_hi_value, GD_lo_value) \
({ \
	NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value); \
	NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#define	NATIVE_WRITE_GD_REG(GD_hi, GD_lo) \
({ \
	NATIVE_WRITE_GD_REG_VALUE(GD_hi.GD_hi_half, GD_lo.GD_lo_half); \
})

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define	NATIVE_NV_READ_PSP_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(psp.lo)
#define	NATIVE_NV_READ_PSP_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(psp.hi)

#define	NATIVE_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value) \
		NATIVE_SET_DSREG_OPEN(psp.lo, PSP_lo_value)
#define	NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(PSP_hi_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(psp.hi, PSP_hi_value)

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define	NATIVE_NV_READ_PSHTP_REG_VALUE()	NATIVE_GET_DSREG_OPEN(pshtp)

#define	NATIVE_WRITE_PSHTP_REG_VALUE(PSHTP_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(pshtp, PSHTP_value, 5)

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define	NATIVE_NV_READ_PCSP_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(pcsp.lo)
#define	NATIVE_NV_READ_PCSP_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(pcsp.hi)

#define	NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value) \
		NATIVE_SET_DSREG_OPEN(pcsp.lo, PCSP_lo_value)
#define	NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(pcsp.hi, PCSP_hi_value)

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	NATIVE_NV_READ_CR0_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cr0.lo)
#define	NATIVE_NV_READ_CR0_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cr0.hi)
#define	NATIVE_NV_READ_CR1_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cr1.lo)
#define	NATIVE_NV_READ_CR1_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cr1.hi)

#define	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(CR0_lo_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(cr0.lo, CR0_lo_value)
#define	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(CR0_hi_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(cr0.hi, CR0_hi_value)
#define	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(CR1_lo_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(cr1.lo, CR1_lo_value)
#define	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(CR1_hi_value) \
		NATIVE_SET_DSREG_OPEN_NOIRQ(cr1.hi, CR1_hi_value)

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define	NATIVE_READ_PCSHTP_REG_SVALUE()				\
		PCSHTP_SIGN_EXTEND(NATIVE_GET_SREG_OPEN(pcshtp))

#define	NATIVE_WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)		\
		NATIVE_SET_SREG_CLOSED_NOEXC(pcshtp, PCSHTP_svalue, 5)

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */
#define	NATIVE_NV_READ_CTPR_REG_VALUE(reg_no)	\
	NATIVE_GET_DSREG_OPEN(ctpr##reg_no)

#define	NATIVE_READ_CTPR_HI_REG_VALUE(reg_no)	\
	NATIVE_GET_DSREG_CLOSED_CLOBBERS(ctpr##reg_no.hi, \
					 __stringify(ctpr##reg_no))

#define	NATIVE_WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)	\
	NATIVE_SET_DSREG_OPEN(ctpr##reg_no, CTPR_value)

#define	NATIVE_WRITE_CTPR_HI_REG_VALUE(reg_no, value)	\
	NATIVE_SET_DSREG_CLOSED_EXC_CLOBBERS(ctpr##reg_no.hi, value, \
					     4, __stringify(ctpr##reg_no))

/*
 * Read/write low/high double-word Trap Info Registers (TIRs)
 */
#define	NATIVE_READ_TIR_LO_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(tir.lo)
#define	NATIVE_READ_TIR_HI_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(tir.hi)

#define	NATIVE_WRITE_TIR_LO_REG_VALUE(TIR_lo_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(tir.lo, TIR_lo_value, 4)
#define	NATIVE_WRITE_TIR_HI_REG_VALUE(TIR_hi_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(tir.hi, TIR_hi_value, 4)

/*
 * Read/write low/high double-word Trap Info Registers (TIRs)
 * as the low/high word structure
 */
#define	NATIVE_READ_TIR_LO_REG() \
({ \
	e2k_tir_lo_t	TIR_lo; \
	TIR_lo.TIR_lo_reg = NATIVE_READ_TIR_LO_REG_VALUE(); \
	TIR_lo; \
})
#define	NATIVE_READ_TIR_HI_REG() \
({ \
	e2k_tir_hi_t	TIR_hi; \
	TIR_hi.TIR_hi_reg = NATIVE_READ_TIR_HI_REG_VALUE(); \
	TIR_hi; \
})
static inline e2k_tir_lo_t
native_read_TIR_lo_reg(void)
{
	return NATIVE_READ_TIR_LO_REG();
}
static inline e2k_tir_hi_t
native_read_TIR_hi_reg(void)
{
	return NATIVE_READ_TIR_HI_REG();
}

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define	NATIVE_NV_READ_USD_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(usd.lo)
#define	NATIVE_NV_READ_USD_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(usd.hi)

#define	NATIVE_NV_WRITE_USD_LO_REG_VALUE(USD_lo_value) \
		NATIVE_SET_DSREG_OPEN(usd.lo, USD_lo_value)
#define	NATIVE_NV_WRITE_USD_HI_REG_VALUE(USD_hi_value) \
		NATIVE_SET_DSREG_OPEN(usd.hi, USD_hi_value)
#define	NATIVE_NV_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	NATIVE_NV_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	NATIVE_NV_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	NATIVE_NV_WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	NATIVE_NV_WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})

#define	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(usbr, usd_hi, usd_lo) \
do { \
	NATIVE_NV_WRITE_USBR_REG_VALUE(usbr); \
	NATIVE_NV_WRITE_USD_HI_REG_VALUE(usd_hi); \
	NATIVE_NV_WRITE_USD_LO_REG_VALUE(usd_lo); \
} while (0)

#define	NATIVE_NV_WRITE_USBR_USD_REG(usbr, usd_hi, usd_lo) \
do { \
	NATIVE_NV_WRITE_USBR_REG(usbr); \
	NATIVE_NV_WRITE_USD_HI_REG(usd_hi); \
	NATIVE_NV_WRITE_USD_LO_REG(usd_lo); \
} while (0)

/*
 * Read/write low/high double-word Protected User Stack Descriptor
 * Register (PUSD)
 */
#define	NATIVE_NV_READ_PUSD_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(usd.lo)
#define	NATIVE_NV_READ_PUSD_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(usd.hi)

#define	NATIVE_NV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value) \
		NATIVE_SET_DSREG_OPEN(usd.lo, PUSD_lo_value)
#define	NATIVE_NV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value) \
		NATIVE_SET_DSREG_OPEN(usd.hi, PUSD_hi_value)

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	NATIVE_NV_READ_USBR_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sbr)
#define	NATIVE_NV_READ_SBR_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sbr)

#define	NATIVE_NV_WRITE_USBR_REG_VALUE(USBR_value) \
		NATIVE_SET_DSREG_OPEN(sbr, USBR_value)
#define	NATIVE_NV_WRITE_SBR_REG_VALUE(SBR_value) \
		NATIVE_SET_DSREG_OPEN(sbr, SBR_value)
#define	NATIVE_NV_WRITE_USBR_REG(USBR)	\
		NATIVE_NV_WRITE_USBR_REG_VALUE(USBR.USBR_reg)

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	NATIVE_READ_WD_REG_VALUE()		NATIVE_GET_DSREG_OPEN(wd)

#define	NATIVE_WRITE_WD_REG_VALUE(WD_value) \
	NATIVE_SET_DSREG_CLOSED_NOEXC(wd, WD_value, 5)

/*
 * Read/write double-word Loop Status Register (LSR/LSR1)
 */
#define	NATIVE_READ_LSR_REG_VALUE()		NATIVE_GET_DSREG_OPEN(lsr)
#define	NATIVE_READ_LSR1_REG_VALUE()		NATIVE_GET_DSREG_OPEN(lsr1)

#define	NATIVE_WRITE_LSR_REG_VALUE(LSR_value) \
		NATIVE_SET_DSREG_OPEN(lsr, LSR_value)
#define	NATIVE_WRITE_LSR1_REG_VALUE(LSR1_value)	\
		NATIVE_SET_DSREG_OPEN(lsr1, LSR1_value)

/*
 * Read/write double-word Loop Status Register (ILCR/ILCR1)
 */
#define	NATIVE_READ_ILCR_REG_VALUE()		NATIVE_GET_DSREG_OPEN(ilcr)
#define	NATIVE_READ_ILCR1_REG_VALUE()		NATIVE_GET_DSREG_CLOSED(ilcr1)

#define	NATIVE_WRITE_ILCR_REG_VALUE(ILCR_value)	\
		NATIVE_SET_DSREG_OPEN(ilcr, ILCR_value)
#define	NATIVE_WRITE_ILCR1_REG_VALUE(ILCR1_value)	\
		NATIVE_SET_DSREG_CLOSED_EXC(ilcr1, ILCR1_value, 4)

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	NATIVE_NV_READ_OSR0_REG_VALUE()		NATIVE_GET_DSREG_OPEN(osr0)

#define	NATIVE_NV_WRITE_OSR0_REG_VALUE(osr0_value)	\
		NATIVE_SET_DSREG_OPEN(osr0, osr0_value)

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	NATIVE_READ_OSEM_REG_VALUE()		NATIVE_GET_SREG_CLOSED(osem)

#define	NATIVE_WRITE_OSEM_REG_VALUE(osem_value)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(osem, osem_value, 5)

/*
 * Read/write word Base Global Register (BGR)
 */
#define	NATIVE_READ_BGR_REG_VALUE()		NATIVE_GET_SREG_OPEN(bgr)

#define	NATIVE_WRITE_BGR_REG_VALUE(BGR_value)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(bgr, BGR_value, 5)

/*
 * Read CPU current clock register (CLKR)
 */
#define	NATIVE_READ_CLKR_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(clkr)
#define	NATIVE_WRITE_CLKR_REG_VALUE()	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(clkr, 0, 4)

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	NATIVE_READ_SCLKR_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sclkr)
#define	NATIVE_READ_SCLKM1_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sclkm1)
#define	NATIVE_READ_SCLKM2_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sclkm2)
#define	NATIVE_READ_SCLKM3_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sclkm3)

#define	NATIVE_WRITE_SCLKR_REG_VALUE(reg_value) \
		NATIVE_SET_DSREG_CLOSED_NOEXC(sclkr, reg_value, 4)
#define	NATIVE_WRITE_SCLKM1_REG_VALUE(reg_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm1, reg_value, 4)
#define	NATIVE_WRITE_SCLKM2_REG_VALUE(reg_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm2, reg_value, 4)
#define	NATIVE_WRITE_SCLKM3_REG_VALUE(reg_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(sclkm3, reg_value, 4)

extern unsigned long native_read_SCLKR_reg_value(void);
extern unsigned long native_read_SCLKM1_reg_value(void);
extern unsigned long native_read_SCLKM2_reg_value(void);
extern void native_write_SCLKR_reg_value(unsigned long reg_value);
extern void native_write_SCLKM1_reg_value(unsigned long reg_value);
extern void native_write_SCLKM2_reg_value(unsigned long reg_value);

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	NATIVE_READ_CU_HW0_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(cu_hw0)
#define	NATIVE_READ_CU_HW1_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(cu_hw1)

#define	NATIVE_WRITE_CU_HW0_REG_VALUE(reg) \
		NATIVE_SET_DSREG_CLOSED_EXC(cu_hw0, reg, 5)
#define	NATIVE_WRITE_CU_HW1_REG_VALUE(reg) \
		NATIVE_SET_DSREG_CLOSED_EXC(cu_hw1, reg, 5)

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	NATIVE_READ_RPR_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(rpr.lo)
#define	NATIVE_READ_RPR_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(rpr.hi)
#define	NATIVE_READ_SBBP_REG_VALUE()	NATIVE_GET_DSREG_OPEN(sbbp)
#define	NATIVE_WRITE_SBBP_REG_VALUE(x)	\
		NATIVE_SET_DSREG_CLOSED_EXC(sbbp, (x), 0)

#define	NATIVE_WRITE_RPR_LO_REG_VALUE(RPR_lo_value) \
		NATIVE_SET_DSREG_OPEN(rpr.lo, RPR_lo_value)
#define	NATIVE_WRITE_RPR_HI_REG_VALUE(RPR_hi_value) \
		NATIVE_SET_DSREG_OPEN(rpr.hi, RPR_hi_value)

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	NATIVE_READ_IP_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(ip)
#define	NATIVE_NV_READ_IP_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ip)

/*
 * Read debug and monitors registers
 */
#define	NATIVE_READ_DIBCR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(dibcr)
#define	NATIVE_READ_DIBSR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(dibsr)
#define	NATIVE_READ_DIMCR_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(dimcr)
#define	NATIVE_READ_DIBAR0_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar0)
#define	NATIVE_READ_DIBAR1_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar1)
#define	NATIVE_READ_DIBAR2_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar2)
#define	NATIVE_READ_DIBAR3_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar3)
#define	NATIVE_READ_DIMAR0_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dimar0)
#define	NATIVE_READ_DIMAR1_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dimar1)

#define	NATIVE_WRITE_DIBCR_REG_VALUE(DIBCR_value)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(dibcr, DIBCR_value, 4)
#define	NATIVE_WRITE_DIBSR_REG_VALUE(DIBSR_value)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(dibsr, DIBSR_value, 4)
#define	NATIVE_WRITE_DIMCR_REG_VALUE(DIMCR_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dimcr, DIMCR_value, 4)
#define	NATIVE_WRITE_DIBAR0_REG_VALUE(DIBAR0_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dibar0, DIBAR0_value, 4)
#define	NATIVE_WRITE_DIBAR1_REG_VALUE(DIBAR1_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dibar1, DIBAR1_value, 4)
#define	NATIVE_WRITE_DIBAR2_REG_VALUE(DIBAR2_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dibar2, DIBAR2_value, 4)
#define	NATIVE_WRITE_DIBAR3_REG_VALUE(DIBAR3_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dibar3, DIBAR3_value, 4)
#define	NATIVE_WRITE_DIMAR0_REG_VALUE(DIMAR0_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dimar0, DIMAR0_value, 4)
#define	NATIVE_WRITE_DIMAR1_REG_VALUE(DIMAR1_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(dimar1, DIMAR1_value, 4)

/*
 * Read/write double-word Compilation Unit Table Register (CUTD/OSCUTD)
 */
#define	NATIVE_NV_READ_CUTD_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cutd)
#define	NATIVE_READ_OSCUTD_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(oscutd)

#define	NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD_value)	\
		NATIVE_SET_DSREG_OPEN_NOIRQ(cutd, CUTD_value)
#define	NATIVE_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
		NATIVE_SET_DSREG_CLOSED_NOEXC(oscutd, CUTD_value, 5)

/*
 * Read/write word Compilation Unit Index Register (CUIR/OSCUIR)
 */
#define	NATIVE_READ_CUIR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(cuir)
#define	NATIVE_READ_OSCUIR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(oscuir)
#define	NATIVE_WRITE_CUIR_REG_VALUE(x) \
		NATIVE_SET_SREG_CLOSED_NOEXC(cuir, (x), 5)
#define	NATIVE_WRITE_OSCUIR_REG_VALUE(x) \
		NATIVE_SET_SREG_CLOSED_NOEXC(oscuir, (x), 5)

/*
 * Read/write word Processor State Register (PSR)
 */
#define	NATIVE_NV_READ_PSR_REG_VALUE()	NATIVE_GET_SREG_OPEN(psr)

#define	NATIVE_WRITE_PSR_REG_VALUE(PSR_value)	\
		NATIVE_SET_SREG_CLOSED_EXC(psr, PSR_value, 5)
#define	NATIVE_WRITE_PSR_IRQ_BARRIER(psr_val)	\
		NATIVE_SET_PSR_IRQ_BARRIER(psr_val)


/*
 * Read/write word User Processor State Register (UPSR)
 */
/* upsr reg - byte register, but linux used long flag
 * to save arch_local_irq_save.To avoid casting to long(redundant stx command)
 * we can used read long register.Suprisingly, but size of image.boot decreased
 * 4096 byte
 */
#define	NATIVE_NV_READ_UPSR_REG_VALUE()	NATIVE_GET_DSREG_OPEN(upsr)
#define	NATIVE_WRITE_UPSR_REG_VALUE(UPSR_value)	\
		NATIVE_SET_SREG_CLOSED_EXC(upsr, UPSR_value, 4)
#define	NATIVE_WRITE_UPSR_IRQ_BARRIER(upsr_val)	\
		NATIVE_SET_UPSR_IRQ_BARRIER(upsr_val)

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	NATIVE_NV_READ_PFPFR_REG_VALUE()	NATIVE_GET_SREG_OPEN(pfpfr)
#define	NATIVE_NV_READ_FPCR_REG_VALUE()		NATIVE_GET_SREG_OPEN(fpcr)
#define	NATIVE_NV_READ_FPSR_REG_VALUE()		NATIVE_GET_SREG_OPEN(fpsr)

#define	NATIVE_NV_WRITE_PFPFR_REG_VALUE(PFPFR_value)	\
		NATIVE_SET_SREG_OPEN(pfpfr, PFPFR_value)
#define	NATIVE_NV_WRITE_FPCR_REG_VALUE(FPCR_value)	\
		NATIVE_SET_SREG_OPEN(fpcr, FPCR_value)
#define	NATIVE_NV_WRITE_FPSR_REG_VALUE(FPSR_value)	\
		NATIVE_SET_SREG_OPEN(fpsr, FPSR_value)

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	NATIVE_READ_CS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cs.lo)
#define	NATIVE_READ_CS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(cs.hi)
#define	NATIVE_READ_DS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ds.lo)
#define	NATIVE_READ_DS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ds.hi)
#define	NATIVE_READ_ES_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(es.lo)
#define	NATIVE_READ_ES_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(es.hi)
#define	NATIVE_READ_FS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(fs.lo)
#define	NATIVE_READ_FS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(fs.hi)
#define	NATIVE_READ_GS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(gs.lo)
#define	NATIVE_READ_GS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(gs.hi)
#define	NATIVE_READ_SS_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ss.lo)
#define	NATIVE_READ_SS_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(ss.hi)

#define	NATIVE_CL_WRITE_CS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(cs.lo, sd)
#define	NATIVE_CL_WRITE_CS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(cs.hi, sd)
#define	NATIVE_CL_WRITE_DS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ds.lo, sd)
#define	NATIVE_CL_WRITE_DS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ds.hi, sd)
#define	NATIVE_CL_WRITE_ES_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(es.lo, sd)
#define	NATIVE_CL_WRITE_ES_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(es.hi, sd)
#define	NATIVE_CL_WRITE_FS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(fs.lo, sd)
#define	NATIVE_CL_WRITE_FS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(fs.hi, sd)
#define	NATIVE_CL_WRITE_GS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(gs.lo, sd)
#define	NATIVE_CL_WRITE_GS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(gs.hi, sd)
#define	NATIVE_CL_WRITE_SS_LO_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ss.lo, sd)
#define	NATIVE_CL_WRITE_SS_HI_REG_VALUE(sd) NATIVE_SET_DSREG_OPEN(ss.hi, sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	NATIVE_READ_IDR_REG_VALUE()	NATIVE_GET_DSREG_OPEN(idr)

/*
 * Read/Write Processor Core Mode Register (CORE_MODE)
 */
#if __LCC__ > 125 || __LCC__ == 125 && __LCC_MINOR__ >= 8
# define NATIVE_READ_CORE_MODE_REG_VALUE() NATIVE_GET_SREG_OPEN(core_mode)
#else
# define NATIVE_READ_CORE_MODE_REG_VALUE() NATIVE_GET_SREG_CLOSED(core_mode)
#endif
#define	NATIVE_WRITE_CORE_MODE_REG_VALUE(modes)	\
		NATIVE_SET_SREG_CLOSED_NOEXC(core_mode, modes, 5)

#endif	/*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_NATIVE_CPU_REGS_ACCESS_H_ */
