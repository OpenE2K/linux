
#ifndef	_E2K_CPU_REGS_ACCESS_H_
#define	_E2K_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/bitops.h>
#include <asm/cpu_regs_types.h>
#include <asm/native_cpu_regs_access.h>

#ifndef __ASSEMBLY__

#if CONFIG_CPU_ISET >= 3
# define native_read_CORE_MODE_reg_value() \
		NATIVE_READ_CORE_MODE_REG_VALUE()
# define native_write_CORE_MODE_reg_value(modes) \
		NATIVE_WRITE_CORE_MODE_REG_VALUE((modes));
#else
# define native_read_CORE_MODE_reg_value() \
		(machine.rrd(E2K_REG_CORE_MODE))
# define native_write_CORE_MODE_reg_value(modes) \
		(machine.rwd(E2K_REG_CORE_MODE, modes))
#endif
#define	native_read_OSCUTD_reg_value()	\
		(machine.rrd(E2K_REG_OSCUTD))
#define	native_write_OSCUTD_reg_value(modes)	\
		(machine.rwd(E2K_REG_OSCUTD, modes))
#define	native_read_OSCUIR_reg_value()	\
		(machine.rrd(E2K_REG_OSCUIR))
#define	native_write_OSCUIR_reg_value()	\
		(machine.rwd(E2K_REG_OSCUIR))

#define	boot_native_read_CORE_MODE_reg_value()	\
({ \
	typeof(boot_machine.boot_rrd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rrd); \
	func(E2K_REG_CORE_MODE); \
})
#define	boot_native_write_CORE_MODE_reg_value(modes)	\
({ \
	typeof(boot_machine.boot_rwd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rwd); \
	func(E2K_REG_CORE_MODE, modes); \
})
#define	boot_native_read_OSCUTD_reg_value()	\
({ \
	typeof(boot_machine.boot_rrd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rrd); \
	func(E2K_REG_OSCUTD); \
})
#define	boot_native_write_OSCUTD_reg_value(v)	\
({ \
	typeof(boot_machine.boot_rwd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rwd); \
	func(E2K_REG_OSCUTD, (v)); \
})
#define	boot_native_read_OSCUIR_reg_value()	\
({ \
	typeof(boot_machine.boot_rrd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rrd); \
	func(E2K_REG_OSCUIR); \
})
#define	boot_native_write_OSCUIR_reg_value(v)	\
({ \
	typeof(boot_machine.boot_rwd) func; \
	func = boot_native_vp_to_pp(boot_machine.boot_rwd); \
	func(E2K_REG_OSCUIR, v); \
})

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/cpu_regs_access.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/cpu_regs_access.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */

/*
 * Set flags of updated VCPU registers
 */
#define	PUT_UPDATED_CPU_REGS_FLAGS(flags)

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define	READ_PSHTP_REG_VALUE()		NATIVE_NV_READ_PSHTP_REG_VALUE()

#define	WRITE_PSHTP_REG_VALUE(PSHTP_value)				\
		NATIVE_WRITE_PSHTP_REG_VALUE(PSHTP_value)

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define	READ_PCSHTP_REG_SVALUE()	NATIVE_READ_PCSHTP_REG_SVALUE()

#define	WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)			\
		NATIVE_WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

#define	READ_OSCUD_LO_REG_VALUE()	NATIVE_READ_OSCUD_LO_REG_VALUE()
#define	READ_OSCUD_HI_REG_VALUE()	NATIVE_READ_OSCUD_HI_REG_VALUE()
#define	BOOT_READ_OSCUD_LO_REG_VALUE()	NATIVE_READ_OSCUD_LO_REG_VALUE()
#define	BOOT_READ_OSCUD_HI_REG_VALUE()	NATIVE_READ_OSCUD_HI_REG_VALUE()

#define	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)			\
		NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)			\
		NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)
#define	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)		\
		NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)		\
		NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	READ_OSGD_LO_REG_VALUE()	NATIVE_READ_OSGD_LO_REG_VALUE()
#define	READ_OSGD_HI_REG_VALUE()	NATIVE_READ_OSGD_HI_REG_VALUE()
#define	BOOT_READ_OSGD_LO_REG_VALUE()	NATIVE_READ_OSGD_LO_REG_VALUE()
#define	BOOT_READ_OSGD_HI_REG_VALUE()	NATIVE_READ_OSGD_HI_REG_VALUE()

#define	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)			\
		NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)			\
		NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)
#define	BOOT_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)			\
		NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	BOOT_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)			\
		NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)

/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */

#define	READ_CUD_LO_REG_VALUE()		NATIVE_READ_CUD_LO_REG_VALUE()
#define	READ_CUD_HI_REG_VALUE()		NATIVE_READ_CUD_HI_REG_VALUE()
#define	BOOT_READ_CUD_LO_REG_VALUE()	NATIVE_READ_CUD_LO_REG_VALUE()
#define	BOOT_READ_CUD_HI_REG_VALUE()	NATIVE_READ_CUD_HI_REG_VALUE()

#define	WRITE_CUD_LO_REG_VALUE(CUD_lo_value)				\
		NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	WRITE_CUD_HI_REG_VALUE(CUD_hi_value)				\
		NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)
#define	BOOT_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)			\
		NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	BOOT_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)			\
		NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define	READ_GD_LO_REG_VALUE()		NATIVE_READ_GD_LO_REG_VALUE()
#define	READ_GD_HI_REG_VALUE()		NATIVE_READ_GD_HI_REG_VALUE()
#define	BOOT_READ_GD_LO_REG_VALUE()	NATIVE_READ_GD_LO_REG_VALUE()
#define	BOOT_READ_GD_HI_REG_VALUE()	NATIVE_READ_GD_HI_REG_VALUE()

#define	WRITE_GD_LO_REG_VALUE(GD_lo_value)				\
		NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	WRITE_GD_HI_REG_VALUE(GD_hi_value)				\
		NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value)
#define	BOOT_WRITE_GD_LO_REG_VALUE(GD_lo_value)			\
		NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	BOOT_WRITE_GD_HI_REG_VALUE(GD_hi_value)			\
		NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value)

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define	READ_PSP_LO_REG_VALUE()		NATIVE_NV_READ_PSP_LO_REG_VALUE()
#define	READ_PSP_HI_REG_VALUE()		NATIVE_NV_READ_PSP_HI_REG_VALUE()
#define	BOOT_READ_PSP_LO_REG_VALUE()	NATIVE_NV_READ_PSP_LO_REG_VALUE()
#define	BOOT_READ_PSP_HI_REG_VALUE()	NATIVE_NV_READ_PSP_HI_REG_VALUE()

#define	WRITE_PSP_LO_REG_VALUE(PSP_lo_value)			\
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define	WRITE_PSP_HI_REG_VALUE(PSP_hi_value)			\
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)
#define	BOOT_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)			\
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define	BOOT_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)		\
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define	READ_PCSP_LO_REG_VALUE()	NATIVE_NV_READ_PCSP_LO_REG_VALUE()
#define	READ_PCSP_HI_REG_VALUE()	NATIVE_NV_READ_PCSP_HI_REG_VALUE()
#define	BOOT_READ_PCSP_LO_REG_VALUE()	NATIVE_NV_READ_PCSP_LO_REG_VALUE()
#define	BOOT_READ_PCSP_HI_REG_VALUE()	NATIVE_NV_READ_PCSP_HI_REG_VALUE()

#define	WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)			\
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define	WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)			\
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)
#define	BOOT_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)			\
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define	BOOT_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)			\
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	READ_CR0_LO_REG_VALUE()		NATIVE_NV_READ_CR0_LO_REG_VALUE()
#define	READ_CR0_HI_REG_VALUE()		NATIVE_NV_READ_CR0_HI_REG_VALUE()
#define	READ_CR1_LO_REG_VALUE()		NATIVE_NV_READ_CR1_LO_REG_VALUE()
#define	READ_CR1_HI_REG_VALUE()		NATIVE_NV_READ_CR1_HI_REG_VALUE()

#define	WRITE_CR0_LO_REG_VALUE(CR0_lo_value)			\
		NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)
#define	WRITE_CR0_HI_REG_VALUE(CR0_hi_value)			\
		NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)
#define	WRITE_CR1_LO_REG_VALUE(CR1_lo_value)			\
		NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)
#define	WRITE_CR1_HI_REG_VALUE(CR1_hi_value)			\
		NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */
#define	READ_CTPR_REG_VALUE(reg_no)	NATIVE_NV_READ_CTPR_REG_VALUE(reg_no)

#define	WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)			\
		NATIVE_WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define	READ_USD_LO_REG_VALUE()		NATIVE_NV_READ_USD_LO_REG_VALUE()
#define	READ_USD_HI_REG_VALUE()		NATIVE_NV_READ_USD_HI_REG_VALUE()
#define	BOOT_READ_USD_LO_REG_VALUE()	NATIVE_NV_READ_USD_LO_REG_VALUE()
#define	BOOT_READ_USD_HI_REG_VALUE()	NATIVE_NV_READ_USD_HI_REG_VALUE()

#define	WRITE_USD_LO_REG_VALUE(USD_lo_value)				\
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	WRITE_USD_HI_REG_VALUE(USD_hi_value)				\
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(USD_hi_value)
#define	BOOT_WRITE_USD_LO_REG_VALUE(USD_lo_value)			\
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	BOOT_WRITE_USD_HI_REG_VALUE(USD_hi_value)			\
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(USD_hi_value)

/*
 * Read/write low/high double-word Protected User Stack Descriptor
 * Register (PUSD)
 */
#define	READ_PUSD_LO_REG_VALUE()	NATIVE_NV_READ_PUSD_LO_REG_VALUE()
#define	READ_PUSD_HI_REG_VALUE()	NATIVE_NV_READ_PUSD_HI_REG_VALUE()

#define	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value)			\
		NATIVE_NV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value)
#define	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value)			\
		NATIVE_NV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value)

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	READ_USBR_REG_VALUE()		NATIVE_NV_READ_USBR_REG_VALUE()
#define	READ_SBR_REG_VALUE()		NATIVE_NV_READ_SBR_REG_VALUE()
#define	BOOT_READ_USBR_REG_VALUE()	NATIVE_NV_READ_USBR_REG_VALUE()
#define	BOOT_READ_SBR_REG_VALUE()	NATIVE_NV_READ_SBR_REG_VALUE()

#define	WRITE_USBR_REG_VALUE(USBR_value)			\
		NATIVE_NV_WRITE_USBR_REG_VALUE(USBR_value)
#define	WRITE_SBR_REG_VALUE(SBR_value)				\
		NATIVE_NV_WRITE_SBR_REG_VALUE(SBR_value)
#define	BOOT_WRITE_USBR_REG_VALUE(USBR_value)			\
		NATIVE_NV_WRITE_USBR_REG_VALUE(USBR_value)
#define	BOOT_WRITE_SBR_REG_VALUE(SBR_value)			\
		NATIVE_NV_WRITE_SBR_REG_VALUE(SBR_value)

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	READ_WD_REG_VALUE()		NATIVE_READ_WD_REG_VALUE()

#define	WRITE_WD_REG_VALUE(WD_value)					\
		NATIVE_WRITE_WD_REG_VALUE(WD_value)

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
/*
 * Read/write double-word Loop Status Register (LSR)
 */
#define	READ_LSR_REG_VALUE()		NATIVE_READ_LSR_REG_VALUE()

#define	WRITE_LSR_REG_VALUE(LSR_value)				\
		NATIVE_WRITE_LSR_REG_VALUE(LSR_value)

/*
 * Read/write double-word Initial Loop Counters Register (ILCR)
 */
#define	READ_ILCR_REG_VALUE()	NATIVE_READ_ILCR_REG_VALUE()

#define	WRITE_ILCR_REG_VALUE(ILCR_value)			\
		NATIVE_WRITE_ILCR_REG_VALUE(ILCR_value)

/*
 * Write double-word LSR/ILCR registers in complex
 */
#define	WRITE_LSR_LSR1_ILCR_ILCR1_REGS_VALUE(lsr, lsr1, ilcr, ilcr1) \
		NATIVE_WRITE_LSR_LSR1_ILCR_ILCR1_REGS_VALUE(lsr, lsr1, \
								ilcr, ilcr1)
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	READ_CURRENT_REG_VALUE()	NATIVE_NV_READ_OSR0_REG_VALUE()
#define	BOOT_READ_CURRENT_REG_VALUE()	NATIVE_NV_READ_OSR0_REG_VALUE()

#define	WRITE_CURRENT_REG_VALUE(osr0_value)			\
		NATIVE_NV_WRITE_OSR0_REG_VALUE(osr0_value)
#define	BOOT_WRITE_CURRENT_REG_VALUE(osr0_value)		\
		NATIVE_NV_WRITE_OSR0_REG_VALUE(osr0_value)

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	READ_OSEM_REG_VALUE()	NATIVE_READ_OSEM_REG_VALUE()

#define	WRITE_OSEM_REG_VALUE(osem_value)			\
		NATIVE_WRITE_OSEM_REG_VALUE(osem_value)

/*
 * Read/write word Base Global Register (BGR)
 */
#define	READ_BGR_REG_VALUE()		NATIVE_READ_BGR_REG_VALUE()
#define	BOOT_READ_BGR_REG_VALUE()	NATIVE_READ_BGR_REG_VALUE()

#define	WRITE_BGR_REG_VALUE(BGR_value)				\
		NATIVE_WRITE_BGR_REG_VALUE(BGR_value)
#define	BOOT_WRITE_BGR_REG_VALUE(BGR_value)			\
		NATIVE_WRITE_BGR_REG_VALUE(BGR_value)

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	READ_CLKR_REG_VALUE()	NATIVE_READ_CLKR_REG_VALUE()

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	READ_SCLKR_REG_VALUE()	NATIVE_READ_SCLKR_REG_VALUE()
#define	READ_SCLKM1_REG_VALUE()	NATIVE_READ_SCLKM1_REG_VALUE()
#define	READ_SCLKM2_REG_VALUE()	NATIVE_READ_SCLKM2_REG_VALUE()
#define	READ_SCLKM3_REG_VALUE()	NATIVE_READ_SCLKM3_REG_VALUE()

#define	WRITE_SCLKR_REG_VALUE(reg_value)	\
		NATIVE_WRITE_SCLKR_REG_VALUE(reg_value)
#define	WRITE_SCLKM1_REG_VALUE(reg_value)	\
		NATIVE_WRITE_SCLKM1_REG_VALUE(reg_value)
#define	WRITE_SCLKM2_REG_VALUE(reg_value)	\
		NATIVE_WRITE_SCLKM2_REG_VALUE(reg_value)
#define	WRITE_SCLKM3_REG_VALUE(reg_value)	\
		NATIVE_WRITE_SCLKM3_REG_VALUE(reg_value)

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	READ_CU_HW0_REG_VALUE()		NATIVE_READ_CU_HW0_REG_VALUE()
#define	READ_CU_HW1_REG_VALUE()		NATIVE_READ_CU_HW1_REG_VALUE()

#define	WRITE_CU_HW0_REG_VALUE(reg)	NATIVE_WRITE_CU_HW0_REG_VALUE(reg)
#define	WRITE_CU_HW1_REG_VALUE(reg)	NATIVE_WRITE_CU_HW1_REG_VALUE(reg)

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	READ_RPR_LO_REG_VALUE()	NATIVE_READ_RPR_LO_REG_VALUE()
#define	READ_RPR_HI_REG_VALUE()	NATIVE_READ_RPR_HI_REG_VALUE()
#define	READ_SBBP_REG_VALUE()	NATIVE_READ_SBBP_REG_VALUE()

#define	WRITE_RPR_LO_REG_VALUE(RPR_lo_value)			\
		NATIVE_WRITE_RPR_LO_REG_VALUE(RPR_lo_value)
#define	WRITE_RPR_HI_REG_VALUE(RPR_hi_value)			\
		NATIVE_WRITE_RPR_HI_REG_VALUE(RPR_hi_value)

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	READ_IP_REG_VALUE()		NATIVE_NV_READ_IP_REG_VALUE()

/*
 * Read debug and monitors regigisters
 */
#define	READ_DIBCR_REG_VALUE()	NATIVE_READ_DIBCR_REG_VALUE()
#define	READ_DIBSR_REG_VALUE()	NATIVE_READ_DIBSR_REG_VALUE()
#define	READ_DIMCR_REG_VALUE()	NATIVE_READ_DIMCR_REG_VALUE()
#define	READ_DIBAR0_REG_VALUE()	NATIVE_READ_DIBAR0_REG_VALUE()
#define	READ_DIBAR1_REG_VALUE()	NATIVE_READ_DIBAR1_REG_VALUE()
#define	READ_DIBAR2_REG_VALUE()	NATIVE_READ_DIBAR2_REG_VALUE()
#define	READ_DIBAR3_REG_VALUE()	NATIVE_READ_DIBAR3_REG_VALUE()
#define	READ_DIMAR0_REG_VALUE()	NATIVE_READ_DIMAR0_REG_VALUE()
#define	READ_DIMAR1_REG_VALUE()	NATIVE_READ_DIMAR1_REG_VALUE()

#define	WRITE_DIBCR_REG_VALUE(DIBCR_value)				\
		NATIVE_WRITE_DIBCR_REG_VALUE(DIBCR_value)
#define	WRITE_DIBSR_REG_VALUE(DIBSR_value)				\
		NATIVE_WRITE_DIBSR_REG_VALUE(DIBSR_value)
#define	WRITE_DIMCR_REG_VALUE(DIMCR_value)				\
		NATIVE_WRITE_DIMCR_REG_VALUE(DIMCR_value)
#define	WRITE_DIBAR0_REG_VALUE(DIBAR0_value)				\
		NATIVE_WRITE_DIBAR0_REG_VALUE(DIBAR0_value)
#define	WRITE_DIBAR1_REG_VALUE(DIBAR1_value)				\
		NATIVE_WRITE_DIBAR1_REG_VALUE(DIBAR1_value)
#define	WRITE_DIBAR2_REG_VALUE(DIBAR2_value)				\
		NATIVE_WRITE_DIBAR2_REG_VALUE(DIBAR2_value)
#define	WRITE_DIBAR3_REG_VALUE(DIBAR3_value)				\
		NATIVE_WRITE_DIBAR3_REG_VALUE(DIBAR3_value)
#define	WRITE_DIMAR0_REG_VALUE(DIMAR0_value)				\
		NATIVE_WRITE_DIMAR0_REG_VALUE(DIMAR0_value)
#define	WRITE_DIMAR1_REG_VALUE(DIMAR1_value)				\
		NATIVE_WRITE_DIMAR1_REG_VALUE(DIMAR1_value)

/*
 * Read/write double-word Compilation Unit Table Register (CUTD)
 */
#define	READ_CUTD_REG_VALUE()	NATIVE_NV_READ_CUTD_REG_VALUE()

#define	WRITE_CUTD_REG_VALUE(CUTD_value)				\
		NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD_value)

/*
 * Read word Compilation Unit Index Register (CUIR)
 */
#define	READ_CUIR_REG_VALUE()	NATIVE_READ_CUIR_REG_VALUE()

/*
 * Read/write word Processor State Register (PSR)
 */
#define	READ_PSR_REG_VALUE()		NATIVE_NV_READ_PSR_REG_VALUE()
#define	BOOT_READ_PSR_REG_VALUE()	NATIVE_NV_READ_PSR_REG_VALUE()

#define	WRITE_PSR_REG_VALUE(PSR_value)				\
		NATIVE_WRITE_PSR_REG_VALUE(PSR_value)
#define	BOOT_WRITE_PSR_REG_VALUE(PSR_value)				\
		NATIVE_WRITE_PSR_REG_VALUE(PSR_value)
#define	WRITE_PSR_IRQ_BARRIER(PSR_value)				\
		NATIVE_WRITE_PSR_IRQ_BARRIER(PSR_value)

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	READ_UPSR_REG_VALUE()		NATIVE_NV_READ_UPSR_REG_VALUE()
#define	BOOT_READ_UPSR_REG_VALUE()	NATIVE_NV_READ_UPSR_REG_VALUE()

#define	WRITE_UPSR_REG_VALUE(UPSR_value)			\
		NATIVE_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	BOOT_WRITE_UPSR_REG_VALUE(UPSR_value)			\
		NATIVE_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	WRITE_UPSR_IRQ_BARRIER(UPSR_value)			\
		NATIVE_WRITE_UPSR_IRQ_BARRIER(UPSR_value)

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	READ_PFPFR_REG_VALUE()	NATIVE_NV_READ_PFPFR_REG_VALUE()
#define	READ_FPCR_REG_VALUE()	NATIVE_NV_READ_FPCR_REG_VALUE()
#define	READ_FPSR_REG_VALUE()	NATIVE_NV_READ_FPSR_REG_VALUE()

#define	WRITE_PFPFR_REG_VALUE(PFPFR_value)				\
		NATIVE_NV_WRITE_PFPFR_REG_VALUE(PFPFR_value)
#define	WRITE_FPCR_REG_VALUE(FPCR_value)				\
		NATIVE_NV_WRITE_FPCR_REG_VALUE(FPCR_value)
#define	WRITE_FPSR_REG_VALUE(FPSR_value)				\
		NATIVE_NV_WRITE_FPSR_REG_VALUE(FPSR_value)

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
#define	READ_IDR_REG_VALUE()		NATIVE_READ_IDR_REG_VALUE()
#define	BOOT_READ_IDR_REG_VALUE()	NATIVE_READ_IDR_REG_VALUE()

/*
 * Processor Core Mode Register (CORE_MODE)
 */
#define	READ_CORE_MODE_REG_VALUE()	native_read_CORE_MODE_reg_value()
#define	BOOT_READ_CORE_MODE_REG_VALUE()	boot_native_read_CORE_MODE_reg_value()
#define	WRITE_CORE_MODE_REG_VALUE(modes)	\
		native_write_CORE_MODE_reg_value(modes)
#define	BOOT_WRITE_CORE_MODE_REG_VALUE(modes)	\
		boot_native_write_CORE_MODE_reg_value(modes)

/*
 * OS Compilation Unit Table Descriptor Register (OSCUTD)
 */
#define	READ_OSCUTD_REG_VALUE()		native_read_OSCUTD_reg_value()
#define	BOOT_READ_OSCUTD_REG_VALUE()	boot_native_read_OSCUTD_reg_value()
#define	WRITE_OSCUTD_REG_VALUE(desc)	\
		native_write_OSCUTD_reg_value(desc)
#define	BOOT_WRITE_OSCUTD_REG_VALUE(desc)	\
		boot_native_write_OSCUTD_reg_value((desc))

/*
 * OS Compilation Unit Index Register (OSCUIR)
 */
#define	READ_OSCUIR_REG_VALUE()		native_read_OSCUIR_reg_value()
#define	WRITE_OSCUIR_REG_VALUE(v)	native_write_OSCUIR_reg_value((v))
#define	BOOT_READ_OSCUIR_REG_VALUE()	boot_native_read_OSCUIR_reg_value()
#define	BOOT_WRITE_OSCUIR_REG_VALUE(v)	boot_native_write_OSCUIR_reg_value((v))

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/*  __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif  /* _E2K_CPU_REGS_ACCESS_H_ */
