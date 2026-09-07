/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	_E2K_CPU_REGS_ACCESS_H_
#define	_E2K_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#include <linux/printk.h>

#if !defined(_INCLUDED_IN_CPU_REGS_H_)
#error file arch/e2k/include/asm/cpu_regs_access.h included directly
#endif

#include <asm/native_cpu_regs_access.h>

#ifndef __ASSEMBLY__

#define	boot_native_read_CORE_MODE_reg	native_read_CORE_MODE_reg
#define	boot_native_write_CORE_MODE_reg	native_write_CORE_MODE_reg
#define	boot_native_read_OSCUTD_reg	native_read_OSCUTD_reg
#define	boot_native_write_OSCUTD_reg	native_write_OSCUTD_reg
#define	boot_native_read_OSCUIR_reg	native_read_OSCUIR_reg
#define	boot_native_write_OSCUIR_reg	native_write_OSCUIR_reg

/*
 * Processor Core Mode Register (CORE_MODE)
 */
#define	read_CORE_MODE_reg		native_read_CORE_MODE_reg
#define	boot_read_CORE_MODE_reg		boot_native_read_CORE_MODE_reg
#define	write_CORE_MODE_reg		native_write_CORE_MODE_reg
#define	boot_write_CORE_MODE_reg	boot_native_write_CORE_MODE_reg

/*
 * OS Compilation Unit Table Descriptor Register (OSCUTD)
 */
#define	read_OSCUTD_reg			native_read_OSCUTD_reg
#define	boot_read_OSCUTD_reg		boot_native_read_OSCUTD_reg
#define	write_OSCUTD_reg		native_write_OSCUTD_reg
#define	boot_write_OSCUTD_reg		boot_native_write_OSCUTD_reg

/*
 * OS Compilation Unit Index Register (OSCUIR)
 */
#define	read_OSCUIR_reg			native_read_OSCUIR_reg
#define	write_OSCUIR_reg		native_write_OSCUIR_reg
#define	boot_read_OSCUIR_reg		boot_native_read_OSCUIR_reg
#define	boot_write_OSCUIR_reg		boot_native_write_OSCUIR_reg

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define	read_PSHTP_reg		native_read_PSHTP_reg
#define	write_PSHTP_reg		native_write_PSHTPP_reg
#define	strip_PSHTP_window	native_strip_PSHTP_window

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define	read_PCSHTP_reg		native_read_PCSHTP_reg
#define	write_PCSHTP_reg	native_write_PCSHTP_reg
#define	strip_PCSHTP_window	native_strip_PCSHTP_window

/*
 * Read/write low/high double-word Compilation Unit Register (CUTD)
 */

#define	read_CUTD_reg		native_read_CUTD_reg
#define	boot_read_CUTD_reg	native_read_CUTD_reg

#define	write_CUTD_reg		native_write_CUTD_reg
#define	boot_write_CUTD_reg	native_write_CUTD_reg

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	read_OSGD_reg		native_read_OSGD_reg
#define	boot_read_OSGD_reg	native_read_OSGD_reg

#define	write_OSGD_reg		native_write_OSGD_reg
#define	boot_write_OSGD_reg	native_write_OSGD_reg

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define	read_GD_reg		native_read_GD_reg
#define	boot_read_GD_reg	native_read_GD_reg

#define	write_GD_reg		native_write_GD_reg
#define	boot_write_GD_reg	native_write_GD_reg

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define	read_PSP_reg		native_read_PSP_reg
#define	boot_read_PSP_reg	native_read_PSP_reg
#define	write_PSP_reg		native_write_PSP_reg
#define	boot_write_PSP_reg	native_write_PSP_reg

#define write_hw_stacks		native_write_hw_stacks
#define write_hw_stacks_cr	native_write_hw_stacks_cr
#define write_hw_stacks_cr__no_wait	native_write_hw_stacks_cr__no_wait
#define write_cr		native_write_cr
#define write_cr__no_wait	native_write_cr__no_wait

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define	read_PCSP_reg		native_read_PCSP_reg
#define	boot_read_PCSP_reg	native_read_PCSP_reg
#define	write_PCSP_reg		native_write_PCSP_reg
#define	boot_write_PCSP_reg	native_write_PCSP_reg

#define	boot_write_hw_stacks	native_write_hw_stacks

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	read_CR0_reg		native_read_CR0_reg
#define	boot_read_CR0_reg	native_read_CR0_reg
#define	write_CR0_reg		native_write_CR0_reg
#define	boot_write_CR0_reg	native_write_CR0_reg
#define	write_CR0_ip		native_write_CR0_ip

#define	read_CR1_reg		native_read_CR1_reg
#define	boot_read_CR1_reg	native_read_CR1_reg
#define	write_CR1_reg		native_write_CR1_reg
#define	boot_write_CR1_reg	native_write_CR1_reg

/*
 * Read data stack size of current frame (USFS)
 */
#define read_USFS_reg		native_read_USFS_reg
#define zero_USFS_reg		native_zero_USFS_reg

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */

#define	read_CTPR_reg(reg_no)	native_read_CTPR_reg(reg_no)
#define	write_CTPR_reg(reg_no)	native_write_CTPR_reg(reg_no)

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define	read_USD_reg		native_read_USD_reg
#define	boot_read_USD_reg	native_read_USD_reg
#define	write_USD_reg		native_write_USD_reg
#define	boot_write_USD_reg	native_write_USD_reg

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	read_USBR_reg		native_read_USBR_reg
#define	boot_read_USBR_reg	native_read_USBR_reg
#define	write_USBR_reg		native_write_USBR_reg
#define	boot_write_USBR_reg	native_write_USBR_reg

#define	read_SBR_reg		read_USBR_reg
#define	boot_read_SBR_reg	boot_read_USBR_reg
#define	write_SBR_reg		write_USBR_reg
#define	boot_write_SBR_reg	boot_write_USBR_reg

#define write_USBR_USD_values	native_write_USBR_USD_values

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	read_WD_reg		native_read_WD_reg
#define	write_WD_reg		native_write_WD_reg

/* CUD */

#define	read_CUD_reg		native_read_CUD_reg
#define	write_CUD_reg		native_write_CUD_reg
#define	boot_write_CUD_reg	native_write_CUD_reg

/* OSCUD */
#define	read_OSCUD_reg		native_read_OSCUD_reg
#define	boot_read_OSCUD_reg	native_read_OSCUD_reg
#define	write_OSCUD_reg		native_write_OSCUD_reg
#define	boot_write_OSCUD_reg	native_write_OSCUD_reg

/* Read DIMTP */
#define	read_DIMTP_reg	native_read_DIMTP_reg

/* MADMR and OS_MADMR */
#define	read_MADMR_reg		native_read_MADMR_reg
#define	write_MADMR_reg		native_write_MADMR_reg
#define	read_OS_MADMR_reg	native_read_OS_MADMR_reg
#define	write_OS_MADMR_reg	native_write_OS_MADMR_reg


/*
 * Read/write double-word Random state Predicates Register (RNDPR)
 */
static inline e2k_rndpr_t read_RNDPR_reg(void)
{
	return (e2k_rndpr_t) { .word = NATIVE_GET_DREG_OPEN(wd) };
}

static inline void write_RNDPR_reg(e2k_rndpr_t rndpr)
{
	NATIVE_SET_DREG_NOEXC(3, rndpr, AW(rndpr));
}


#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
/*
 * Read/write double-word Loop Status Register (LSR)
 */
#define	READ_LSR_REG_VALUE()	NATIVE_READ_LSR_REG_VALUE()

#define	WRITE_LSR_REG_VALUE	NATIVE_WRITE_LSR_REG_VALUE

/*
 * Read/write double-word Initial Loop Counters Register (ILCR)
 */
#define	READ_ILCR_REG_VALUE()	NATIVE_READ_ILCR_REG_VALUE()

#define	WRITE_ILCR_REG_VALUE	NATIVE_WRITE_ILCR_REG_VALUE

/*
 * Write double-word LSR/ILCR registers in complex
 */
#define	WRITE_LSR_LSR1_ILCR_ILCR1_REGS_VALUE(lsr, lsr1, ilcr, ilcr1) \
		NATIVE_WRITE_LSR_LSR1_ILCR_ILCR1_REGS_VALUE(lsr, lsr1, \
								ilcr, ilcr1)
#endif /* NEED_PARAVIRT_LOOP_REGISTERS */

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0/1). OSR0/1 == CURRENT
 */
#define	read_CURRENT_reg_value		native_read_CURRENT_reg_value
#define	boot_read_CURRENT_reg_value	native_read_CURRENT_reg_value

#define	write_CURRENT_reg_value		native_write_CURRENT_reg_value
#define	boot_write_CURRENT_reg_value	native_write_CURRENT_reg_value

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	read_OSEM_reg_value		native_read_OSEM_reg_value
#define	write_OSEM_reg_value		native_write_OSEM_reg_value

/*
 * Read/write word Base Global Register (BGR)
 */
#define	read_BGR_reg			native_read_BGR_reg
#define	boot_read_BGR_reg		native_read_BGR_reg

#define	write_BGR_reg		native_write_BGR_reg
#define	init_BGR_reg		native_init_BGR_reg
#define	boot_write_BGR_reg	native_write_BGR_reg
#define	boot_init_BGR_reg	native_init_BGR_reg

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	read_CLKR_reg_value	native_read_CLKR_reg_value

/*
 * Read/Write system clock registers (SCLKR, SCLKMx)
 */

#define	read_SCLKR_reg		native_read_SCLKR_reg
#define	read_SCLKM1_reg		native_read_SCLKM1_reg
#define	read_SCLKM2_reg		native_read_SCLKM2_reg
#define	read_SCLKM3_reg_value	native_read_SCLKM3_reg_value

#define	write_SCLKR_reg		native_write_SCLKR_reg
#define	write_SCLKM1_reg	native_write_SCLKM1_reg
#define	write_SCLKM2_reg	native_write_SCLKM2_reg
#define	write_SCLKM3_reg_value	native_write_SCLKM3_reg_value




/*
 * Read/write CPU enhanced system clock registers (T_ABS, T_OFF)
 */
#define	read_T_ABS	native_read_T_ABS_reg_value
#define	read_T_OFF	native_read_T_OFF_reg_value

#define	write_T_OFF	native_write_T_OFF_reg_value

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	read_CU_HW0_reg		native_read_CU_HW0_reg
#define	read_CU_HW1_reg_value	native_read_CU_HW1_reg_value

#define	write_CU_HW0_reg	native_write_CU_HW0_reg
#define	write_CU_HW1_reg_value	native_write_CU_HW1_reg_value

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	read_RPR_reg	native_read_RPR_reg
#define	write_RPR_reg	native_write_RPR_reg

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	read_IP_reg_value	native_read_IP_reg_value

/*
 * Read debug and monitors regigisters
 */
#define	read_DIBCR_reg		native_read_DIBCR_reg
#define	read_DIBSR_reg		native_read_DIBSR_reg
#define	read_DIMCR_reg		native_read_DIMCR_reg
#define	read_DIMCR1_reg		native_read_DIMCR1_reg
#define	read_DIBAR0_reg		native_read_DIBAR0_reg
#define	read_DIBAR1_reg		native_read_DIBAR1_reg
#define	read_DIBAR2_reg		native_read_DIBAR2_reg
#define	read_DIBAR3_reg		native_read_DIBAR3_reg
#define	read_DIMAR0_reg		native_read_DIMAR0_reg
#define	read_DIMAR1_reg		native_read_DIMAR1_reg
#define	read_DIMAR2_reg		native_read_DIMAR2_reg
#define	read_DIMAR3_reg		native_read_DIMAR3_reg

#define	write_DIBCR_reg		native_write_DIBCR_reg
#define	write_DIBSR_reg		native_write_DIBSR_reg
#define	clear_DIBSR_reg		native_clear_DIBSR_reg
#define	clear_DIBCR_reg		native_clear_DIBCR_reg
#define	write_DIMCR_reg		native_write_DIMCR_reg
#define	write_DIMCR1_reg	native_write_DIMCR1_reg
#define	clear_DIMCR_reg		native_clear_DIMCR_reg
#define	clear_DIMCR1_reg	native_clear_DIMCR1_reg
#define	write_DIBAR0_reg	native_write_DIBAR0_reg
#define	write_DIBAR1_reg	native_write_DIBAR1_reg
#define	write_DIBAR2_reg	native_write_DIBAR2_reg
#define	write_DIBAR3_reg	native_write_DIBAR3_reg
#define	write_DIMAR0_reg	native_write_DIMAR0_reg
#define	write_DIMAR1_reg	native_write_DIMAR1_reg
#define	write_DIMAR2_reg	native_write_DIMAR2_reg
#define	write_DIMAR3_reg	native_write_DIMAR3_reg

/*
 * Read/write double-word Compilation Unit Table Register (CUTD)
 */
#define	read_CUTD_reg	native_read_CUTD_reg
#define	write_CUTD_reg	native_write_CUTD_reg

/*
 * Read word Compilation Unit Index Register (CUIR)
 */
#define	read_CUIR_reg			native_read_CUIR_reg

/*
 * Read/write word Processor State Register (PSR)
 */
#define	read_PSR_reg			native_read_PSR_reg
#define	boot_read_PSR_reg		native_read_PSR_reg

#define	write_PSR_reg			native_write_PSR_reg
#define	write_irq_barrier_PSR_reg	native_write_irq_barrier_PSR_reg

/*
 *   *   Read/Write Hypercall Entries Mask register (HCEM)
 */
#define	read_HCEM_reg_value		native_read_HCEM_reg_value
#define	write_HCEM_reg_value		native_write_HCEM_reg_value

/*
 *     Read/Write Hypercall Entries Base register (HCEB)
 */

#define	read_HCEB_reg_value		native_read_HCEB_reg_value
#define	write_HCEB_reg_value		native_write_HCEB_reg_value

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	read_UPSR_reg			native_read_UPSR_reg
#define	boot_read_UPSR_reg		native_read_UPSR_reg

#define	write_UPSR_reg			native_write_UPSR_reg
#define	boot_write_UPSR_reg		native_write_UPSR_reg
#define	write_irq_barrier_UPSR_reg	native_write_irq_barrier_UPSR_reg

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	read_PFPFR_reg		native_read_PFPFR_reg
#define	read_FPCR_reg		native_read_FPCR_reg
#define	read_FPSR_reg		native_read_FPSR_reg

#define write_FPU_regs		native_write_FPU_regs

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	READ_CS_LO_REG_VALUE()	NATIVE_READ_CS_LO_REG_VALUE()
#define	READ_CS_HI_REG_VALUE()	NATIVE_READ_CS_HI_REG_VALUE()
#define	READ_DS_LO_REG_VALUE()	NATIVE_READ_DS_LO_REG_VALUE()
#define	READ_DS_HI_REG_VALUE()	NATIVE_READ_DS_HI_REG_VALUE()
#define	READ_ES_LO_REG_VALUE()	NATIVE_READ_ES_LO_REG_VALUE()
#define	READ_ES_HI_REG_VALUE()	NATIVE_READ_ES_HI_REG_VALUE()
#define	READ_FS_LO_REG_VALUE()	NATIVE_READ_FS_LO_REG_VALUE()
#define	READ_FS_HI_REG_VALUE()	NATIVE_READ_FS_HI_REG_VALUE()
#define	READ_GS_LO_REG_VALUE()	NATIVE_READ_GS_LO_REG_VALUE()
#define	READ_GS_HI_REG_VALUE()	NATIVE_READ_GS_HI_REG_VALUE()
#define	READ_SS_LO_REG_VALUE()	NATIVE_READ_SS_LO_REG_VALUE()
#define	READ_SS_HI_REG_VALUE()	NATIVE_READ_SS_HI_REG_VALUE()

#define	WRITE_CS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_CS_LO_REG_VALUE(sd)
#define	WRITE_CS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_CS_HI_REG_VALUE(sd)
#define	WRITE_DS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_DS_LO_REG_VALUE(sd)
#define	WRITE_DS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_DS_HI_REG_VALUE(sd)
#define	WRITE_ES_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_ES_LO_REG_VALUE(sd)
#define	WRITE_ES_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_ES_HI_REG_VALUE(sd)
#define	WRITE_FS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_FS_LO_REG_VALUE(sd)
#define	WRITE_FS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_FS_HI_REG_VALUE(sd)
#define	WRITE_GS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_GS_LO_REG_VALUE(sd)
#define	WRITE_GS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_GS_HI_REG_VALUE(sd)
#define	WRITE_SS_LO_REG_VALUE(sd)	NATIVE_CL_WRITE_SS_LO_REG_VALUE(sd)
#define	WRITE_SS_HI_REG_VALUE(sd)	NATIVE_CL_WRITE_SS_HI_REG_VALUE(sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	read_IDR_reg			native_read_IDR_reg
#define	boot_read_IDR_reg		native_read_IDR_reg

#endif /*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _E2K_CPU_REGS_ACCESS_H_ */
