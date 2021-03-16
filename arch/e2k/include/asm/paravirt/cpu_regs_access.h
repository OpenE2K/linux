
#ifndef	_E2K_PARAVIRT_CPU_REGS_ACCESS_H_
#define	_E2K_PARAVIRT_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

#include <asm/types.h>
#include <asm/pv_info.h>
#include <asm/cpu_regs_types.h>
#include <asm/paravirt/pv_ops.h>

static inline void PV_PUT_UPDATED_CPU_REGS_FLAGS(unsigned long flags)
{
	if (pv_cpu_ops.put_updated_cpu_regs_flags == NULL)
		return;
	pv_cpu_ops.put_updated_cpu_regs_flags(flags);
}

static inline unsigned long long PV_READ_OSCUD_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSCUD_lo_reg_value();
}

static inline unsigned long long PV_READ_OSCUD_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSCUD_hi_reg_value();
}

static inline void PV_WRITE_OSCUD_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_OSCUD_lo_reg_value(reg_value);
}

static inline void PV_WRITE_OSCUD_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_OSCUD_hi_reg_value(reg_value);
}

static inline unsigned long long BOOT_PV_READ_OSCUD_LO_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_OSCUD_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_OSCUD_HI_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_OSCUD_hi_reg_value);
}

static inline void BOOT_PV_WRITE_OSCUD_LO_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_OSCUD_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_OSCUD_HI_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_OSCUD_hi_reg_value, reg_value);
}

static inline unsigned long long PV_READ_OSGD_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSGD_lo_reg_value();
}

static inline unsigned long long PV_READ_OSGD_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSGD_hi_reg_value();
}
static inline unsigned long long BOOT_PV_READ_OSGD_LO_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_OSGD_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_OSGD_HI_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_OSGD_hi_reg_value);
}

static inline void PV_WRITE_OSGD_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_OSGD_lo_reg_value(reg_value);
}

static inline void PV_WRITE_OSGD_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_OSGD_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_OSGD_LO_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_OSGD_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_OSGD_HI_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_OSGD_hi_reg_value, reg_value);
}

static inline unsigned long long PV_READ_CUD_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_CUD_lo_reg_value();
}

static inline unsigned long long PV_READ_CUD_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_CUD_hi_reg_value();
}

static inline unsigned long long BOOT_PV_READ_CUD_LO_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_CUD_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_CUD_HI_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_CUD_hi_reg_value);
}

static inline void PV_WRITE_CUD_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CUD_lo_reg_value(reg_value);
}

static inline void PV_WRITE_CUD_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CUD_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_CUD_LO_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_CUD_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_CUD_HI_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_CUD_hi_reg_value, reg_value);
}

static inline unsigned long long PV_READ_GD_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_GD_lo_reg_value();
}

static inline unsigned long long PV_READ_GD_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_GD_hi_reg_value();
}

static inline unsigned long long BOOT_PV_READ_GD_LO_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_GD_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_GD_HI_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_GD_hi_reg_value);
}

static inline void PV_WRITE_GD_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_GD_lo_reg_value(reg_value);
}

static inline void PV_WRITE_GD_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_GD_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_GD_LO_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_GD_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_GD_HI_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_GD_hi_reg_value, reg_value);
}

static inline unsigned long long PV_READ_PSP_LO_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PSP_LO_REG_VALUE();
	else
		return pv_cpu_ops.read_PSP_lo_reg_value();
}

static inline unsigned long long PV_READ_PSP_HI_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PSP_HI_REG_VALUE();
	else
		return pv_cpu_ops.read_PSP_hi_reg_value();
}

static inline unsigned long long BOOT_PV_READ_PSP_LO_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_PSP_LO_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_PSP_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_PSP_HI_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_PSP_HI_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_PSP_hi_reg_value);
}

static inline void PV_WRITE_PSP_LO_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PSP_lo_reg_value(reg_value);
}

static inline void PV_WRITE_PSP_HI_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PSP_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_PSP_LO_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_PSP_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_PSP_HI_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_PSP_hi_reg_value, reg_value);
}
#define	PV_NV_READ_PSP_LO_REG_VALUE()	PV_READ_PSP_LO_REG_VALUE()
#define	PV_NV_READ_PSP_HI_REG_VALUE()	PV_READ_PSP_HI_REG_VALUE()
#define	PV_READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = PV_READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
#define	PV_READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = PV_READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})
#define	PV_READ_PSP_REG() \
({ \
	psp_struct_t	PSP; \
	PSP.PSP_hi_struct = PV_READ_PSP_HI_REG(); \
	PSP.PSP_lo_struct = PV_READ_PSP_LO_REG(); \
	PSP; \
})
#define	PV_NV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value) \
		PV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define	PV_NV_WRITE_PSP_HI_REG_VALUE(PSP_hi_value) \
		PV_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)
#define	PV_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	PV_WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	PV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	PV_NV_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value)	\
		PV_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value)
#define	PV_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	PV_WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})

static inline unsigned long long PV_READ_PSHTP_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PSHTP_REG_VALUE();
	else
		return pv_cpu_ops.read_PSHTP_reg_value();
}

static inline void PV_WRITE_PSHTP_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_PSHTP_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PSHTP_reg_value(reg_value);
}
#define	PV_NV_READ_PSHTP_REG_VALUE()	PV_READ_PSHTP_REG_VALUE()
#define	PV_READ_PSHTP_REG() \
({ \
	e2k_pshtp_t PSHTP_reg; \
	PSHTP_reg.word = PV_READ_PSHTP_REG_VALUE(); \
	PSHTP_reg; \
})
#define	PV_WRITE_PSHTP_REG(PSHTP_reg) \
({ \
	PV_WRITE_PSHTP_REG_VALUE(AS_WORD(PSHTP_reg)); \
})
#define	PV_STRIP_PSHTP_WINDOW()	PV_WRITE_PSHTP_REG_VALUE(0)

static inline unsigned long long PV_READ_PCSP_LO_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PCSP_LO_REG_VALUE();
	else
		return pv_cpu_ops.read_PCSP_lo_reg_value();
}

static inline unsigned long long PV_READ_PCSP_HI_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PCSP_HI_REG_VALUE();
	else
		return pv_cpu_ops.read_PCSP_hi_reg_value();
}

static inline unsigned long long BOOT_PV_READ_PCSP_LO_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_PCSP_LO_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_PCSP_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_PCSP_HI_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_PCSP_HI_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_PCSP_hi_reg_value);
}

static inline void PV_WRITE_PCSP_LO_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PCSP_lo_reg_value(reg_value);
}

static inline void PV_WRITE_PCSP_HI_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PCSP_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_PCSP_LO_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_PCSP_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_PCSP_HI_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_PCSP_hi_reg_value, reg_value);
}
#define	PV_NV_READ_PCSP_LO_REG_VALUE()	PV_READ_PCSP_LO_REG_VALUE()
#define	PV_NV_READ_PCSP_HI_REG_VALUE()	PV_READ_PCSP_HI_REG_VALUE()
#define	PV_READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t PCSP_lo; \
	PCSP_lo.PCSP_lo_half = PV_READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
#define	PV_READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t PCSP_hi; \
	PCSP_hi.PCSP_hi_half = PV_READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})
#define	PV_READ_PCSP_REG() \
({ \
	pcsp_struct_t	PCSP; \
	PCSP.PCSP_hi_struct = PV_READ_PCSP_HI_REG(); \
	PCSP.PCSP_lo_struct = PV_READ_PCSP_LO_REG(); \
	PCSP; \
})
#define	PV_READ_PCSP_REG_TO(PCSP) \
({ \
	*PCSP = PV_READ_PCSP_REG(); \
})
#define	PV_NV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value) \
		PV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define	PV_NV_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value) \
		PV_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)
#define	PV_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value) \
({ \
	PV_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value); \
	PV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value); \
})
#define	PV_NV_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value)	\
		PV_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value)
#define	PV_WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
		PV_WRITE_PCSP_REG_VALUE(PCSP_hi.PCSP_hi_half, \
						PCSP_lo.PCSP_lo_half)

static inline int PV_READ_PCSHTP_REG_SVALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_READ_PCSHTP_REG_SVALUE();
	else
		return pv_cpu_ops.read_PCSHTP_reg_value();
}

static inline void PV_WRITE_PCSHTP_REG_SVALUE(int reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_PCSHTP_REG_SVALUE(reg_value);
	else
		pv_cpu_ops.write_PCSHTP_reg_value(reg_value);
}

static inline unsigned long long PV_READ_CR0_LO_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_CR0_LO_REG_VALUE();
	else
		return pv_cpu_ops.read_CR0_lo_reg_value();
}

static inline unsigned long long PV_READ_CR0_HI_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_CR0_HI_REG_VALUE();
	else
		return pv_cpu_ops.read_CR0_hi_reg_value();
}

static inline unsigned long long PV_READ_CR1_LO_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_CR1_LO_REG_VALUE();
	else
		return pv_cpu_ops.read_CR1_lo_reg_value();
}

static inline unsigned long long PV_READ_CR1_HI_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_CR1_HI_REG_VALUE();
	else
		return pv_cpu_ops.read_CR1_hi_reg_value();
}

static inline void PV_WRITE_CR0_LO_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_CR0_lo_reg_value(reg_value);
}

static inline void PV_WRITE_CR0_HI_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_CR0_hi_reg_value(reg_value);
}

static inline void PV_WRITE_CR1_LO_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_CR1_lo_reg_value(reg_value);
}

static inline void PV_WRITE_CR1_HI_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_CR1_hi_reg_value(reg_value);
}
#define	PV_NV_READ_CR0_LO_REG_VALUE()	PV_READ_CR0_LO_REG_VALUE()
#define	PV_NV_READ_CR0_HI_REG_VALUE()	PV_READ_CR0_HI_REG_VALUE()
#define	PV_NV_READ_CR1_LO_REG_VALUE()	PV_READ_CR1_LO_REG_VALUE()
#define	PV_NV_READ_CR1_HI_REG_VALUE()	PV_READ_CR1_HI_REG_VALUE()
#define	PV_READ_CR0_LO_REG() \
({ \
	e2k_cr0_lo_t CR0_lo; \
	CR0_lo.CR0_lo_half = PV_READ_CR0_LO_REG_VALUE(); \
	CR0_lo; \
})
#define	PV_READ_CR0_HI_REG() \
({ \
	e2k_cr0_hi_t CR0_hi; \
	CR0_hi.CR0_hi_half = PV_READ_CR0_HI_REG_VALUE(); \
	CR0_hi; \
})
#define	PV_READ_CR1_LO_REG() \
({ \
	e2k_cr1_lo_t CR1_lo; \
	CR1_lo.CR1_lo_half = PV_READ_CR1_LO_REG_VALUE(); \
	CR1_lo; \
})
#define	PV_READ_CR1_HI_REG() \
({ \
	e2k_cr1_hi_t CR1_hi; \
	CR1_hi.CR1_hi_half = PV_READ_CR1_HI_REG_VALUE(); \
	CR1_hi; \
})
#define	PV_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(CR0_lo_value) \
			PV_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)
#define	PV_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(CR0_hi_value) \
			PV_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)
#define	PV_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(CR1_lo_value) \
			PV_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)
#define	PV_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(CR1_hi_value) \
			PV_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)

static inline unsigned long long PV_READ_CTPR_REG_VALUE(int reg_no)
{
	return pv_cpu_ops.read_CTPR_reg_value(reg_no);
}

static inline void PV_WRITE_CTPR_REG_VALUE(int reg_no, unsigned long reg_value)
{
	pv_cpu_ops.write_CTPR_reg_value(reg_no, reg_value);
}

static inline unsigned long long PV_READ_USD_LO_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_USD_LO_REG_VALUE();
	else
		return pv_cpu_ops.read_USD_lo_reg_value();
}

static inline unsigned long long PV_READ_USD_HI_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_USD_HI_REG_VALUE();
	else
		return pv_cpu_ops.read_USD_hi_reg_value();
}

static inline unsigned long long BOOT_PV_READ_USD_LO_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_USD_LO_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_USD_lo_reg_value);
}

static inline unsigned long long BOOT_PV_READ_USD_HI_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_USD_HI_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_USD_hi_reg_value);
}

static inline void PV_WRITE_USD_LO_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_USD_lo_reg_value(reg_value);
}

static inline void PV_WRITE_USD_HI_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_USD_hi_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_USD_LO_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_USD_lo_reg_value, reg_value);
}

static inline void BOOT_PV_WRITE_USD_HI_REG_VALUE(unsigned long reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_USD_hi_reg_value, reg_value);
}
#define	PV_READ_USD_LO_REG() \
({ \
	e2k_usd_lo_t	USD_lo; \
	USD_lo.USD_lo_half = PV_READ_USD_LO_REG_VALUE(); \
	USD_lo; \
})
#define	PV_READ_USD_HI_REG() \
({ \
	e2k_usd_hi_t	USD_hi; \
	USD_hi.USD_hi_half = PV_READ_USD_HI_REG_VALUE(); \
	USD_hi; \
})
#define	PV_READ_USD_REG() \
({ \
	usd_struct_t	USD; \
	USD.USD_hi_struct = PV_READ_USD_HI_REG(); \
	USD.USD_lo_struct = PV_READ_USD_LO_REG(); \
	USD; \
})
#define	PV_NV_WRITE_USD_LO_REG_VALUE(usd_lo_value)	\
		PV_WRITE_USD_LO_REG_VALUE(usd_lo_value)
#define	PV_NV_WRITE_USD_HI_REG_VALUE(usd_hi_value)	\
		PV_WRITE_USD_HI_REG_VALUE(usd_hi_value)
#define	PV_WRITE_USD_LO_REG(USD_lo) \
		PV_WRITE_USD_LO_REG_VALUE(USD_lo.USD_lo_half)
#define	PV_WRITE_USD_HI_REG(USD_hi) \
		PV_WRITE_USD_HI_REG_VALUE(USD_hi.USD_hi_half)
#define	PV_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	PV_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	PV_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	PV_NV_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value)	\
		PV_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value)
#define	PV_WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	PV_WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})

static inline unsigned long long PV_READ_PUSD_LO_REG_VALUE(void)
{
	return PV_READ_USD_LO_REG_VALUE();
}

static inline unsigned long long PV_READ_PUSD_HI_REG_VALUE(void)
{
	return PV_READ_USD_HI_REG_VALUE();
}

static inline void PV_WRITE_PUSD_LO_REG_VALUE(unsigned long reg_value)
{
	PV_WRITE_USD_LO_REG_VALUE(reg_value);
}

static inline void PV_WRITE_PUSD_HI_REG_VALUE(unsigned long reg_value)
{
	PV_WRITE_USD_HI_REG_VALUE(reg_value);
}
#define	PV_READ_PUSD_LO_REG() \
({ \
	e2k_pusd_lo_t	PUSD_lo; \
	PUSD_lo.PUSD_lo_half = PV_READ_PUSD_LO_REG_VALUE(); \
	PUSD_lo; \
})
#define	PV_READ_PUSD_HI_REG() \
({ \
	e2k_pusd_hi_t	PUSD_hi; \
	PUSD_hi.PUSD_hi_half = PV_READ_PUSD_HI_REG_VALUE(); \
	PUSD_hi; \
})
#define	PV_READ_PUSD_REG() \
({ \
	pusd_struct_t	PUSD; \
	PUSD.PUSD_hi_struct = PV_READ_PUSD_HI_REG(); \
	PUSD.PUSD_lo_struct = PV_READ_PUSD_LO_REG(); \
	PUSD; \
})
#define	PV_READ_PUSD_REG_TO(PUSD) \
({ \
	*PUSD = PV_READ_PUSD_REG(); \
})
#define	PV_WRITE_PUSD_LO_REG(PUSD_lo) \
		PV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo.PUSD_lo_half)
#define	PV_WRITE_PUSD_HI_REG(PUSD_hi) \
		PV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi.PUSD_hi_half)
#define	PV_WRITE_PUSD_REG_VALUE(PUSD_hi_value, PUSD_lo_value) \
({ \
	PV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value); \
	PV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value); \
})
#define	PV_WRITE_PUSD_REG(PUSD_hi, PUSD_lo) \
({ \
	PV_WRITE_PUSD_REG_VALUE(PUSD_hi.PUSD_hi_half, \
					PUSD_lo.PUSD_lo_half); \
})

static inline unsigned long long PV_READ_SBR_REG_VALUE(void)
{
	return pv_cpu_ops.read_SBR_reg_value();
}

static inline unsigned long long BOOT_PV_READ_SBR_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_SBR_reg_value);
}

static inline void PV_WRITE_SBR_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SBR_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_SBR_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_SBR_reg_value, reg_value);
}
#define	PV_NV_READ_SBR_REG_VALUE()	PV_READ_SBR_REG_VALUE()
#define	PV_READ_SBR_REG() \
({ \
	e2k_sbr_t SBR; \
	SBR.SBR_reg = PV_READ_SBR_REG_VALUE(); \
	SBR; \
})
#define	PV_NV_WRITE_SBR_REG_VALUE(SBR_value)	\
		PV_WRITE_SBR_REG_VALUE(SBR_value)

static inline unsigned long long PV_READ_USBR_REG_VALUE(void)
{
	return PV_READ_SBR_REG_VALUE();
}

static inline unsigned long long BOOT_PV_READ_USBR_REG_VALUE(void)
{
	return BOOT_PV_READ_SBR_REG_VALUE();
}

static inline void PV_WRITE_USBR_REG_VALUE(unsigned long reg_value)
{
	PV_WRITE_SBR_REG_VALUE(reg_value);
}

static inline void BOOT_PV_WRITE_USBR_REG_VALUE(unsigned long reg_value)
{
	BOOT_PV_WRITE_SBR_REG_VALUE(reg_value);
}
#define	PV_READ_USBR_REG() \
({ \
	e2k_usbr_t USBR; \
	USBR.USBR_reg = PV_READ_USBR_REG_VALUE(); \
	USBR; \
})
#define	PV_WRITE_USBR_REG(USBR)		\
		PV_WRITE_USBR_REG_VALUE(USBR.USBR_reg)

static inline unsigned long long PV_READ_WD_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_READ_WD_REG_VALUE();
	else
		return pv_cpu_ops.read_WD_reg_value();
}

static inline void PV_WRITE_WD_REG_VALUE(unsigned long reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_WD_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_WD_reg_value(reg_value);
}
#define	PV_READ_WD_REG() \
({ \
	e2k_wd_t WD; \
	WD.WD_reg = PV_READ_WD_REG_VALUE(); \
	WD; \
})
#define	PV_WRITE_WD_REG(WD)	\
		PV_WRITE_WD_REG_VALUE(WD.WD_reg)

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
static inline unsigned long long PV_READ_LSR_REG_VALUE(void)
{
	return pv_cpu_ops.read_LSR_reg_value();
}

static inline void PV_WRITE_LSR_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_LSR_reg_value(reg_value);
}

static inline unsigned long long PV_READ_ILCR_REG_VALUE(void)
{
	return pv_cpu_ops.read_ILCR_reg_value();
}

static inline void PV_WRITE_ILCR_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_ILCR_reg_value(reg_value);
}
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */

static inline unsigned long long PV_READ_OSR0_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSR0_reg_value();
}

static inline unsigned long long BOOT_PV_READ_OSR0_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_OSR0_reg_value);
}

static inline void PV_WRITE_OSR0_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_OSR0_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_OSR0_REG_VALUE(unsigned long reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_OSR0_reg_value, reg_value);
}

static inline unsigned int PV_READ_OSEM_REG_VALUE(void)
{
	return pv_cpu_ops.read_OSEM_reg_value();
}

static inline void PV_WRITE_OSEM_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_OSEM_reg_value(reg_value);
}

static inline unsigned int PV_READ_BGR_REG_VALUE(void)
{
	return pv_cpu_ops.read_BGR_reg_value();
}

static inline unsigned int BOOT_PV_READ_BGR_REG_VALUE(void)
{
	return BOOT_PARAVIRT_READ_REG(read_BGR_reg_value);
}

static inline void PV_WRITE_BGR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_BGR_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_BGR_REG_VALUE(unsigned int reg_value)
{
	BOOT_PARAVIRT_WRITE_REG(write_BGR_reg_value, reg_value);
}
#define	PV_READ_BGR_REG() \
({ \
	e2k_bgr_t BGR; \
	BGR.BGR_reg = PV_READ_BGR_REG_VALUE(); \
	BGR; \
})
#define	PV_WRITE_BGR_REG(BGR)	\
		PV_WRITE_BGR_REG_VALUE(BGR.BGR_reg)

static inline unsigned long long PV_READ_CLKR_REG_VALUE(void)
{
	return pv_cpu_ops.read_CLKR_reg_value();
}

static inline void PV_WRITE_CLKR_REG_VALUE(void)
{
	pv_cpu_ops.write_CLKR_reg_value();
}

static inline unsigned long long PV_READ_SCLKR_REG_VALUE(void)
{
	return pv_cpu_ops.read_SCLKR_reg_value();
}

static inline void PV_WRITE_SCLKR_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SCLKR_reg_value(reg_value);
}

static inline unsigned long long PV_READ_SCLKM1_REG_VALUE(void)
{
	return pv_cpu_ops.read_SCLKM1_reg_value();
}

static inline void PV_WRITE_SCLKM1_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SCLKM1_reg_value(reg_value);
}

static inline unsigned long long PV_READ_SCLKM2_REG_VALUE(void)
{
	return pv_cpu_ops.read_SCLKM2_reg_value();
}

static inline unsigned long long PV_READ_SCLKM3_REG_VALUE(void)
{
	return pv_cpu_ops.read_SCLKM3_reg_value();
}

static inline void PV_WRITE_SCLKM2_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SCLKM2_reg_value(reg_value);
}

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
static inline unsigned long long PV_READ_CU_HW0_REG_VALUE(void)
{
	return pv_cpu_ops.read_CU_HW0_reg_value();
}
static inline unsigned long long PV_READ_CU_HW1_REG_VALUE(void)
{
	return pv_cpu_ops.read_CU_HW1_reg_value();
}
static inline void PV_WRITE_CU_HW0_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CU_HW0_reg_value(reg_value);
}
static inline void PV_WRITE_CU_HW1_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CU_HW1_reg_value(reg_value);
}

static inline unsigned long long PV_READ_RPR_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_RPR_lo_reg_value();
}

static inline unsigned long long PV_READ_RPR_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_RPR_hi_reg_value();
}

static inline void PV_WRITE_RPR_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_RPR_lo_reg_value(reg_value);
}
static inline void PV_CL_WRITE_RPR_LO_REG_VALUE(unsigned long reg_value)
{
	PV_WRITE_RPR_LO_REG_VALUE(reg_value);
}

static inline void PV_WRITE_RPR_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_RPR_hi_reg_value(reg_value);
}
static inline void PV_CL_WRITE_RPR_HI_REG_VALUE(unsigned long reg_value)
{
	PV_WRITE_RPR_HI_REG_VALUE(reg_value);
}
#define	PV_READ_RPR_LO_REG() \
({ \
	e2k_rpr_lo_t	RPR_lo; \
	RPR_lo.RPR_lo_half = PV_READ_RPR_LO_REG_VALUE(); \
	RPR_lo; \
})
#define	PV_READ_RPR_HI_REG() \
({ \
	e2k_rpr_hi_t	RPR_hi; \
	RPR_hi.RPR_hi_half = PV_READ_RPR_HI_REG_VALUE(); \
	RPR_hi; \
})
#define	PV_WRITE_RPR_LO_REG(RPR_lo) \
		PV_WRITE_RPR_LO_REG_VALUE(RPR_lo.RPR_lo_half)
#define	PV_CL_WRITE_RPR_LO_REG(RPR_lo) \
		PV_CL_WRITE_RPR_LO_REG_VALUE(RPR_lo.RPR_lo_half)
#define	PV_WRITE_RPR_HI_REG(RPR_hi) \
		PV_WRITE_RPR_HI_REG_VALUE(RPR_hi.RPR_hi_half)
#define	PV_CL_WRITE_RPR_HI_REG(RPR_hi) \
		PV_CL_WRITE_RPR_HI_REG_VALUE(RPR_hi.RPR_hi_half)

static inline unsigned long long PV_READ_SBBP_REG_VALUE(void)
{
	return pv_cpu_ops.read_SBBP_reg_value();
}

static inline unsigned long long PV_READ_IP_REG_VALUE(void)
{
	return pv_cpu_ops.read_IP_reg_value();
}

static inline unsigned int PV_READ_DIBCR_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBCR_reg_value();
}

static inline void PV_WRITE_DIBCR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_DIBCR_reg_value(reg_value);
}

static inline unsigned int PV_READ_DIBSR_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBSR_reg_value();
}

static inline void PV_WRITE_DIBSR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_DIBSR_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIMCR_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIMCR_reg_value();
}

static inline void PV_WRITE_DIMCR_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIMCR_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIBAR0_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBAR0_reg_value();
}

static inline void PV_WRITE_DIBAR0_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIBAR0_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIBAR1_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBAR1_reg_value();
}

static inline void PV_WRITE_DIBAR1_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIBAR1_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIBAR2_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBAR2_reg_value();
}

static inline void PV_WRITE_DIBAR2_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIBAR2_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIBAR3_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIBAR3_reg_value();
}

static inline void PV_WRITE_DIBAR3_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIBAR3_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIMAR0_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIMAR0_reg_value();
}

static inline void PV_WRITE_DIMAR0_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIMAR0_reg_value(reg_value);
}

static inline unsigned long long PV_READ_DIMAR1_REG_VALUE(void)
{
	return pv_cpu_ops.read_DIMAR1_reg_value();
}

static inline void PV_WRITE_DIMAR1_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DIMAR1_reg_value(reg_value);
}

static inline unsigned long long PV_READ_CUTD_REG_VALUE(void)
{
	return pv_cpu_ops.read_CUTD_reg_value();
}

static inline void PV_NV_NOIRQ_WRITE_CUTD_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CUTD_reg_value(reg_value);
}

static inline unsigned int PV_READ_CUIR_REG_VALUE(void)
{
	return pv_cpu_ops.read_CUIR_reg_value();
}

static inline unsigned int PV_READ_UPSR_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_UPSR_REG_VALUE();
	else
		return pv_cpu_ops.read_UPSR_reg_value();
}

static inline unsigned int BOOT_PV_READ_UPSR_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_UPSR_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_UPSR_reg_value);
}

static inline void PV_WRITE_UPSR_REG_VALUE(unsigned int reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_UPSR_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_UPSR_reg_value(reg_value);
}
static inline void PV_WRITE_UPSR_REG(e2k_upsr_t UPSR)
{
	PV_WRITE_UPSR_REG_VALUE(UPSR.UPSR_reg);
}

static inline void BOOT_PV_WRITE_UPSR_REG_VALUE(unsigned int reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_WRITE_UPSR_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_UPSR_reg_value, reg_value);
}
static inline void BOOT_PV_WRITE_UPSR_REG(e2k_upsr_t UPSR)
{
	BOOT_PV_WRITE_UPSR_REG_VALUE(UPSR.UPSR_reg);
}

static inline void PV_WRITE_UPSR_IRQ_BARRIER(unsigned int reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_UPSR_IRQ_BARRIER(reg_value);
	else
		pv_cpu_ops.write_UPSR_irq_barrier(reg_value);
}

static inline unsigned int PV_READ_PSR_REG_VALUE(void)
{
	if (!paravirt_enabled())
		return NATIVE_NV_READ_PSR_REG_VALUE();
	else
		return pv_cpu_ops.read_PSR_reg_value();
}

static inline unsigned int BOOT_PV_READ_PSR_REG_VALUE(void)
{
	if (!boot_paravirt_enabled())
		return NATIVE_NV_READ_PSR_REG_VALUE();
	else
		return BOOT_PARAVIRT_READ_REG(read_PSR_reg_value);
}

static inline void PV_WRITE_PSR_REG_VALUE(unsigned int reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_PSR_REG_VALUE(reg_value);
	else
		pv_cpu_ops.write_PSR_reg_value(reg_value);
}

static inline void BOOT_PV_WRITE_PSR_REG_VALUE(unsigned int reg_value)
{
	if (!boot_paravirt_enabled())
		NATIVE_WRITE_PSR_REG_VALUE(reg_value);
	else
		BOOT_PARAVIRT_WRITE_REG(write_PSR_reg_value, reg_value);
}

static inline void PV_WRITE_PSR_IRQ_BARRIER(unsigned int reg_value)
{
	if (!paravirt_enabled())
		NATIVE_WRITE_PSR_IRQ_BARRIER(reg_value);
	else
		pv_cpu_ops.write_PSR_irq_barrier(reg_value);
}

static inline unsigned int PV_READ_PFPFR_REG_VALUE(void)
{
	return pv_cpu_ops.read_PFPFR_reg_value();
}

static inline void PV_WRITE_PFPFR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_PFPFR_reg_value(reg_value);
}

static inline unsigned int PV_READ_FPCR_REG_VALUE(void)
{
	return pv_cpu_ops.read_FPCR_reg_value();
}

static inline void PV_WRITE_FPCR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_FPCR_reg_value(reg_value);
}

static inline unsigned int PV_READ_FPSR_REG_VALUE(void)
{
	return pv_cpu_ops.read_FPSR_reg_value();
}

static inline void PV_WRITE_FPSR_REG_VALUE(unsigned int reg_value)
{
	pv_cpu_ops.write_FPSR_reg_value(reg_value);
}

static inline unsigned long long PV_READ_CS_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_CS_lo_reg_value();
}

static inline unsigned long long PV_READ_CS_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_CS_hi_reg_value();
}

static inline unsigned long long PV_READ_DS_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_DS_lo_reg_value();
}

static inline unsigned long long PV_READ_DS_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_DS_hi_reg_value();
}

static inline unsigned long long PV_READ_ES_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_ES_lo_reg_value();
}

static inline unsigned long long PV_READ_ES_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_ES_hi_reg_value();
}

static inline unsigned long long PV_READ_FS_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_FS_lo_reg_value();
}

static inline unsigned long long PV_READ_FS_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_FS_hi_reg_value();
}

static inline unsigned long long PV_READ_GS_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_GS_lo_reg_value();
}

static inline unsigned long long PV_READ_GS_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_GS_hi_reg_value();
}

static inline unsigned long long PV_READ_SS_LO_REG_VALUE(void)
{
	return pv_cpu_ops.read_SS_lo_reg_value();
}

static inline unsigned long long PV_READ_SS_HI_REG_VALUE(void)
{
	return pv_cpu_ops.read_SS_hi_reg_value();
}

static inline void PV_WRITE_CS_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CS_lo_reg_value(reg_value);
}

static inline void PV_WRITE_CS_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_CS_hi_reg_value(reg_value);
}

static inline void PV_WRITE_DS_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DS_lo_reg_value(reg_value);
}

static inline void PV_WRITE_DS_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_DS_hi_reg_value(reg_value);
}

static inline void PV_WRITE_ES_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_ES_lo_reg_value(reg_value);
}

static inline void PV_WRITE_ES_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_ES_hi_reg_value(reg_value);
}

static inline void PV_WRITE_FS_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_FS_lo_reg_value(reg_value);
}

static inline void PV_WRITE_FS_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_FS_hi_reg_value(reg_value);
}

static inline void PV_WRITE_GS_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_GS_lo_reg_value(reg_value);
}

static inline void PV_WRITE_GS_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_GS_hi_reg_value(reg_value);
}

static inline void PV_WRITE_SS_LO_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SS_lo_reg_value(reg_value);
}

static inline void PV_WRITE_SS_HI_REG_VALUE(unsigned long reg_value)
{
	pv_cpu_ops.write_SS_hi_reg_value(reg_value);
}

static inline unsigned long long PV_READ_IDR_REG_VALUE(void)
{
	if (pv_cpu_ops.read_IDR_reg_value)
		return pv_cpu_ops.read_IDR_reg_value();
	return 0;
}
static inline unsigned long long BOOT_PV_READ_IDR_REG_VALUE(void)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(boot_read_IDR_reg_value)) {
		return BOOT_PARAVIRT_READ_REG(boot_read_IDR_reg_value);
	}
	return 0;
}

static inline unsigned int PV_READ_CORE_MODE_REG_VALUE(void)
{
	if (pv_cpu_ops.read_CORE_MODE_reg_value)
		return pv_cpu_ops.read_CORE_MODE_reg_value();
	return 0;
}
static inline unsigned int BOOT_PV_READ_CORE_MODE_REG_VALUE(void)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(boot_read_CORE_MODE_reg_value)) {
		return BOOT_PARAVIRT_READ_REG(boot_read_CORE_MODE_reg_value);
	}
	return 0;
}
static inline void PV_WRITE_CORE_MODE_REG_VALUE(unsigned int modes)
{
	if (pv_cpu_ops.write_CORE_MODE_reg_value)
		pv_cpu_ops.write_CORE_MODE_reg_value(modes);
}
static inline void BOOT_PV_WRITE_CORE_MODE_REG_VALUE(unsigned int modes)
{
	if (BOOT_PARAVIRT_GET_CPU_FUNC(boot_write_CORE_MODE_reg_value))
		BOOT_PARAVIRT_WRITE_REG(boot_write_CORE_MODE_reg_value, modes);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

/*
 * Set flags of updated VCPU registers
 */

static inline void PUT_UPDATED_CPU_REGS_FLAGS(unsigned long flags)
{
	PV_PUT_UPDATED_CPU_REGS_FLAGS(flags);
}

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define	READ_PSHTP_REG_VALUE()	PV_READ_PSHTP_REG_VALUE()

#define	WRITE_PSHTP_REG_VALUE(PSHTP_value)	\
				PV_WRITE_PSHTP_REG_VALUE(PSHTP_value)

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define	READ_PCSHTP_REG_SVALUE()	PV_READ_PCSHTP_REG_SVALUE()

#define	WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)	\
		PV_WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

#define	READ_OSCUD_LO_REG_VALUE()	PV_READ_OSCUD_LO_REG_VALUE()
#define	READ_OSCUD_HI_REG_VALUE()	PV_READ_OSCUD_HI_REG_VALUE()
#define	BOOT_READ_OSCUD_LO_REG_VALUE()	BOOT_PV_READ_OSCUD_LO_REG_VALUE()
#define	BOOT_READ_OSCUD_HI_REG_VALUE()	BOOT_PV_READ_OSCUD_HI_REG_VALUE()

#define	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)		\
		PV_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)		\
		PV_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)
#define	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)	\
		BOOT_PV_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)	\
		BOOT_PV_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	READ_OSGD_LO_REG_VALUE()	PV_READ_OSGD_LO_REG_VALUE()
#define	READ_OSGD_HI_REG_VALUE()	PV_READ_OSGD_HI_REG_VALUE()
#define	BOOT_READ_OSGD_LO_REG_VALUE()	BOOT_PV_READ_OSGD_LO_REG_VALUE()
#define	BOOT_READ_OSGD_HI_REG_VALUE()	BOOT_PV_READ_OSGD_HI_REG_VALUE()

#define	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)	\
		PV_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)	\
		PV_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)
#define	BOOT_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)	\
		BOOT_PV_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	BOOT_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)	\
		BOOT_PV_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)

		/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */

#define	READ_CUD_LO_REG_VALUE()		PV_READ_CUD_LO_REG_VALUE()
#define	READ_CUD_HI_REG_VALUE()		PV_READ_CUD_HI_REG_VALUE()
#define	BOOT_READ_CUD_LO_REG_VALUE()	BOOT_PV_READ_CUD_LO_REG_VALUE()
#define	BOOT_READ_CUD_HI_REG_VALUE()	BOOT_PV_READ_CUD_HI_REG_VALUE()

#define	WRITE_CUD_LO_REG_VALUE(CUD_lo_value)		\
		PV_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	WRITE_CUD_HI_REG_VALUE(CUD_hi_value)		\
		PV_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)
#define	BOOT_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)	\
		BOOT_PV_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	BOOT_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)	\
		BOOT_PV_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define	READ_GD_LO_REG_VALUE()		PV_READ_GD_LO_REG_VALUE()
#define	READ_GD_HI_REG_VALUE()		PV_READ_GD_HI_REG_VALUE()
#define	BOOT_READ_GD_LO_REG_VALUE()	BOOT_PV_READ_GD_LO_REG_VALUE()
#define	BOOT_READ_GD_HI_REG_VALUE()	BOOT_PV_READ_GD_HI_REG_VALUE()

#define	WRITE_GD_LO_REG_VALUE(GD_lo_value)		\
		PV_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	WRITE_GD_HI_REG_VALUE(GD_hi_value)		\
		PV_WRITE_GD_HI_REG_VALUE(GD_hi_value)
#define	BOOT_WRITE_GD_LO_REG_VALUE(GD_lo_value)	\
		BOOT_PV_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	BOOT_WRITE_GD_HI_REG_VALUE(GD_hi_value)	\
		BOOT_PV_WRITE_GD_HI_REG_VALUE(GD_hi_value)

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define	READ_PSP_LO_REG_VALUE()		PV_READ_PSP_LO_REG_VALUE()
#define	READ_PSP_HI_REG_VALUE()		PV_READ_PSP_HI_REG_VALUE()
#define	BOOT_READ_PSP_LO_REG_VALUE()	BOOT_PV_READ_PSP_LO_REG_VALUE()
#define	BOOT_READ_PSP_HI_REG_VALUE()	BOOT_PV_READ_PSP_HI_REG_VALUE()

#define	WRITE_PSP_LO_REG_VALUE(PSP_lo_value)		\
		PV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define	WRITE_PSP_HI_REG_VALUE(PSP_hi_value)		\
		PV_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)
#define	BOOT_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)	\
		BOOT_PV_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define	BOOT_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)	\
		BOOT_PV_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define	READ_PCSP_LO_REG_VALUE()	PV_READ_PCSP_LO_REG_VALUE()
#define	READ_PCSP_HI_REG_VALUE()	PV_READ_PCSP_HI_REG_VALUE()
#define	BOOT_READ_PCSP_LO_REG_VALUE()	BOOT_PV_READ_PCSP_LO_REG_VALUE()
#define	BOOT_READ_PCSP_HI_REG_VALUE()	BOOT_PV_READ_PCSP_HI_REG_VALUE()

#define	WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)	 \
		PV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define	WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)	\
		PV_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)
#define	BOOT_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)	\
		BOOT_PV_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define	BOOT_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)	\
		BOOT_PV_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	READ_CR0_LO_REG_VALUE()	PV_READ_CR0_LO_REG_VALUE()
#define	READ_CR0_HI_REG_VALUE()	PV_READ_CR0_HI_REG_VALUE()
#define	READ_CR1_LO_REG_VALUE()	PV_READ_CR1_LO_REG_VALUE()
#define	READ_CR1_HI_REG_VALUE()	PV_READ_CR1_HI_REG_VALUE()

#define	WRITE_CR0_LO_REG_VALUE(CR0_lo_value) \
		PV_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)
#define	WRITE_CR0_HI_REG_VALUE(CR0_hi_value) \
		PV_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)
#define	WRITE_CR1_LO_REG_VALUE(CR1_lo_value) \
		PV_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)
#define	WRITE_CR1_HI_REG_VALUE(CR1_hi_value) \
		PV_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */
#define	READ_CTPR_REG_VALUE(reg_no)	PV_READ_CTPR_REG_VALUE(reg_no)

#define	WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)	\
		PV_WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)

/*
 * Read/write low/high double-word Trap Info Registers (TIRs)
 */
#define	READ_TIR_LO_REG_VALUE()	PV_READ_TIR_LO_REG_VALUE()
#define	READ_TIR_HI_REG_VALUE()	PV_READ_TIR_HI_REG_VALUE()

#define	WRITE_TIR_LO_REG_VALUE(TIR_lo_value) \
		PV_WRITE_TIR_LO_REG_VALUE(TIR_lo_value)
#define	WRITE_TIR_HI_REG_VALUE(TIR_hi_value) \
		PV_WRITE_TIR_HI_REG_VALUE(TIR_hi_value)

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define	READ_USD_LO_REG_VALUE()		PV_READ_USD_LO_REG_VALUE()
#define	READ_USD_HI_REG_VALUE()		PV_READ_USD_HI_REG_VALUE()
#define	BOOT_READ_USD_LO_REG_VALUE()	BOOT_PV_READ_USD_LO_REG_VALUE()
#define	BOOT_READ_USD_HI_REG_VALUE()	BOOT_PV_READ_USD_HI_REG_VALUE()

#define	WRITE_USD_LO_REG_VALUE(USD_lo_value)		\
		PV_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	WRITE_USD_HI_REG_VALUE(USD_hi_value)		\
		PV_WRITE_USD_HI_REG_VALUE(USD_hi_value)
#define	BOOT_WRITE_USD_LO_REG_VALUE(USD_lo_value)	\
		BOOT_PV_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	BOOT_WRITE_USD_HI_REG_VALUE(USD_hi_value)	\
		BOOT_PV_WRITE_USD_HI_REG_VALUE(USD_hi_value)

/*
 * Read/write low/high double-word Protected User Stack Descriptor
 * Register (PUSD)
 */
#define	READ_PUSD_LO_REG_VALUE()	PV_READ_PUSD_LO_REG_VALUE()
#define	READ_PUSD_HI_REG_VALUE()	PV_READ_PUSD_HI_REG_VALUE()

#define	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value) \
		PV_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value)
#define	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value) \
		PV_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value)

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	READ_SBR_REG_VALUE()		PV_READ_SBR_REG_VALUE()
#define	READ_USBR_REG_VALUE()		PV_READ_USBR_REG_VALUE()
#define	BOOT_READ_USBR_REG_VALUE()	BOOT_PV_READ_USBR_REG_VALUE()
#define	BOOT_READ_SBR_REG_VALUE()	BOOT_PV_READ_SBR_REG_VALUE()

#define	WRITE_SBR_REG_VALUE(SBR_value)		\
		PV_WRITE_SBR_REG_VALUE(SBR_value)
#define	WRITE_USBR_REG_VALUE(USBR_value)		\
		PV_WRITE_USBR_REG_VALUE(USBR_value)
#define	BOOT_WRITE_USBR_REG_VALUE(USBR_value)	\
		BOOT_PV_WRITE_USBR_REG_VALUE(USBR_value)
#define	BOOT_WRITE_SBR_REG_VALUE(SBR_value)		\
		BOOT_PV_WRITE_SBR_REG_VALUE(SBR_value)

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	READ_WD_REG_VALUE()		PV_READ_WD_REG_VALUE()
#define	WRITE_WD_REG_VALUE(WD_value)	PV_WRITE_WD_REG_VALUE(WD_value)

/*
 * Read/write double-word Loop Status Register (LSR)
 */
#define	READ_LSR_REG_VALUE()			\
		PV_READ_LSR_REG_VALUE()
#define	WRITE_LSR_REG_VALUE(LSR_value)	\
		PV_WRITE_LSR_REG_VALUE(LSR_value)

/*
 * Read/write double-word Initial Loop Counters Register (ILCR)
 */
#define	READ_ILCR_REG_VALUE()		\
		PV_READ_ILCR_REG_VALUE()
#define	WRITE_ILCR_REG_VALUE(ILCR_value)	\
		PV_WRITE_ILCR_REG_VALUE(ILCR_value)

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	READ_OSR0_REG_VALUE()		PV_READ_OSR0_REG_VALUE()
#define	BOOT_READ_OSR0_REG_VALUE()	BOOT_PV_READ_OSR0_REG_VALUE()

#define	WRITE_OSR0_REG_VALUE(osr0_value)		\
		PV_WRITE_OSR0_REG_VALUE(osr0_value)
#define	BOOT_WRITE_OSR0_REG_VALUE(osr0_value)	\
		BOOT_PV_WRITE_OSR0_REG_VALUE(osr0_value)

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	READ_OSEM_REG_VALUE()		\
		PV_READ_OSEM_REG_VALUE()
#define	WRITE_OSEM_REG_VALUE(OSEM_value)	\
		PV_WRITE_OSEM_REG_VALUE(OSEM_value)

/*
 * Read/write word Base Global Register (BGR)
 */
#define	READ_BGR_REG_VALUE()		PV_READ_BGR_REG_VALUE()
#define	BOOT_READ_BGR_REG_VALUE()	BOOT_PV_READ_BGR_REG_VALUE()

#define	WRITE_BGR_REG_VALUE(BGR_value)	\
		PV_WRITE_BGR_REG_VALUE(BGR_value)
#define	BOOT_WRITE_BGR_REG_VALUE(BGR_value)	\
		BOOT_PV_WRITE_BGR_REG_VALUE(BGR_value)

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	READ_CLKR_REG_VALUE()	PV_READ_CLKR_REG_VALUE()

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	READ_SCLKR_REG_VALUE()	PV_READ_SCLKR_REG_VALUE()
#define	READ_SCLKM1_REG_VALUE()	PV_READ_SCLKM1_REG_VALUE()
#define	READ_SCLKM2_REG_VALUE()	PV_READ_SCLKM2_REG_VALUE()
#define	READ_SCLKM3_REG_VALUE()	PV_READ_SCLKM3_REG_VALUE()

#define	WRITE_SCLKR_REG_VALUE(reg_value)	\
		PV_WRITE_SCLKR_REG_VALUE(reg_value)
#define	WRITE_SCLKM1_REG_VALUE(reg_value)	\
		PV_WRITE_SCLKM1_REG_VALUE(reg_value)
#define	WRITE_SCLKM2_REG_VALUE(reg_value)	\
		PV_WRITE_SCLKM2_REG_VALUE(reg_value)
#define	WRITE_SCLKM3_REG_VALUE(reg_value)	\
		PV_WRITE_SCLKM3_REG_VALUE(reg_value)

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	READ_CU_HW0_REG_VALUE()	PV_READ_CU_HW0_REG_VALUE()
#define	READ_CU_HW1_REG_VALUE()	PV_READ_CU_HW1_REG_VALUE()
#define	WRITE_CU_HW0_REG_VALUE(reg_value)	\
		PV_WRITE_CU_HW0_REG_VALUE(reg_value)
#define	WRITE_CU_HW1_REG_VALUE(reg_value)	\
		PV_WRITE_CU_HW1_REG_VALUE(reg_value)

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	READ_RPR_LO_REG_VALUE()	PV_READ_RPR_LO_REG_VALUE()
#define	READ_RPR_HI_REG_VALUE()	PV_READ_RPR_HI_REG_VALUE()
#define	READ_SBBP_REG_VALUE()	PV_READ_SBBP_REG_VALUE()

#define	WRITE_RPR_LO_REG_VALUE(RPR_lo_value) \
		PV_WRITE_RPR_LO_REG_VALUE(RPR_lo_value)
#define	WRITE_RPR_HI_REG_VALUE(RPR_hi_value) \
		PV_WRITE_RPR_HI_REG_VALUE(RPR_hi_value)

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	READ_IP_REG_VALUE()		PV_READ_IP_REG_VALUE()

/*
 * Read debug and monitors regigisters
 */
#define	READ_DIBCR_REG_VALUE()	PV_READ_DIBCR_REG_VALUE()
#define	READ_DIBSR_REG_VALUE()	PV_READ_DIBSR_REG_VALUE()
#define	READ_DIMCR_REG_VALUE()	PV_READ_DIMCR_REG_VALUE()
#define	READ_DIBAR0_REG_VALUE()	PV_READ_DIBAR0_REG_VALUE()
#define	READ_DIBAR1_REG_VALUE()	PV_READ_DIBAR1_REG_VALUE()
#define	READ_DIBAR2_REG_VALUE()	PV_READ_DIBAR2_REG_VALUE()
#define	READ_DIBAR3_REG_VALUE()	PV_READ_DIBAR3_REG_VALUE()
#define	READ_DIMAR0_REG_VALUE()	PV_READ_DIMAR0_REG_VALUE()
#define	READ_DIMAR1_REG_VALUE()	PV_READ_DIMAR1_REG_VALUE()

#define	WRITE_DIBCR_REG_VALUE(DIBCR_value)	\
		PV_WRITE_DIBCR_REG_VALUE(DIBCR_value)
#define	WRITE_DIBSR_REG_VALUE(DIBSR_value)	\
		PV_WRITE_DIBSR_REG_VALUE(DIBSR_value)
#define	WRITE_DIMCR_REG_VALUE(DIMCR_value)	\
		PV_WRITE_DIMCR_REG_VALUE(DIMCR_value)
#define	WRITE_DIBAR0_REG_VALUE(DIBAR0_value)	\
		PV_WRITE_DIBAR0_REG_VALUE(DIBAR0_value)
#define	WRITE_DIBAR1_REG_VALUE(DIBAR1_value)	\
		PV_WRITE_DIBAR1_REG_VALUE(DIBAR1_value)
#define	WRITE_DIBAR2_REG_VALUE(DIBAR2_value)	\
		PV_WRITE_DIBAR2_REG_VALUE(DIBAR2_value)
#define	WRITE_DIBAR3_REG_VALUE(DIBAR3_value)	\
		PV_WRITE_DIBAR3_REG_VALUE(DIBAR3_value)
#define	WRITE_DIMAR0_REG_VALUE(DIMAR0_value)	\
		PV_WRITE_DIMAR0_REG_VALUE(DIMAR0_value)
#define	WRITE_DIMAR1_REG_VALUE(DIMAR1_value)	\
		PV_WRITE_DIMAR1_REG_VALUE(DIMAR1_value)

/*
 * Read/write double-word Compilation Unit Table Register (CUTD)
 */
#define	READ_CUTD_REG_VALUE()		\
		PV_READ_CUTD_REG_VALUE()
#define	WRITE_CUTD_REG_VALUE(CUTD_value)	\
		PV_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD_value)

/*
 * Read/write word Compilation Unit Index Register (CUIR)
 */
#define	READ_CUIR_REG_VALUE()		\
		PV_READ_CUIR_REG_VALUE()

/*
 * Read/write double-word Compilation Unit Types Descriptor (TSD)
 */
#define	READ_TSD_REG_VALUE()			\
		PV_READ_TSD_REG_VALUE()
#define	WRITE_TSD_REG_VALUE(TSD_value)	\
		PV_WRITE_TSD_REG_VALUE(TSD_value)

/*
 * Read/write word Processor State Register (PSR)
 */
#define	READ_PSR_REG_VALUE()		PV_READ_PSR_REG_VALUE()
#define	BOOT_READ_PSR_REG_VALUE()	BOOT_PV_READ_PSR_REG_VALUE()

#define	WRITE_PSR_REG_VALUE(PSR_value)	\
		PV_WRITE_PSR_REG_VALUE(PSR_value)
#define	BOOT_WRITE_PSR_REG_VALUE(PSR_value)	\
		BOOT_PV_WRITE_PSR_REG_VALUE(PSR_value)
#define	WRITE_PSR_IRQ_BARRIER(PSR_value)	\
		PV_WRITE_PSR_IRQ_BARRIER(PSR_value)

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	READ_UPSR_REG_VALUE()		PV_READ_UPSR_REG_VALUE()
#define	BOOT_READ_UPSR_REG_VALUE()	BOOT_PV_READ_UPSR_REG_VALUE()

#define	WRITE_UPSR_REG_VALUE(UPSR_value)	\
		PV_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	BOOT_WRITE_UPSR_REG_VALUE(UPSR_value)	\
		BOOT_PV_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	WRITE_UPSR_IRQ_BARRIER(PSR_value)	\
		PV_WRITE_UPSR_IRQ_BARRIER(PSR_value)

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	READ_PFPFR_REG_VALUE()	PV_READ_PFPFR_REG_VALUE()
#define	READ_FPCR_REG_VALUE()	PV_READ_FPCR_REG_VALUE()
#define	READ_FPSR_REG_VALUE()	PV_READ_FPSR_REG_VALUE()

#define	WRITE_PFPFR_REG_VALUE(PFPFR_value)	\
		PV_WRITE_PFPFR_REG_VALUE(PFPFR_value)
#define	WRITE_FPCR_REG_VALUE(FPCR_value)	\
		PV_WRITE_FPCR_REG_VALUE(FPCR_value)
#define	WRITE_FPSR_REG_VALUE(FPSR_value)	\
		PV_WRITE_FPSR_REG_VALUE(FPSR_value)

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	READ_CS_LO_REG_VALUE()	PV_READ_CS_LO_REG_VALUE()
#define	READ_CS_HI_REG_VALUE()	PV_READ_CS_HI_REG_VALUE()
#define	READ_DS_LO_REG_VALUE()	PV_READ_DS_LO_REG_VALUE()
#define	READ_DS_HI_REG_VALUE()	PV_READ_DS_HI_REG_VALUE()
#define	READ_ES_LO_REG_VALUE()	PV_READ_ES_LO_REG_VALUE()
#define	READ_ES_HI_REG_VALUE()	PV_READ_ES_HI_REG_VALUE()
#define	READ_FS_LO_REG_VALUE()	PV_READ_FS_LO_REG_VALUE()
#define	READ_FS_HI_REG_VALUE()	PV_READ_FS_HI_REG_VALUE()
#define	READ_GS_LO_REG_VALUE()	PV_READ_GS_LO_REG_VALUE()
#define	READ_GS_HI_REG_VALUE()	PV_READ_GS_HI_REG_VALUE()
#define	READ_SS_LO_REG_VALUE()	PV_READ_SS_LO_REG_VALUE()
#define	READ_SS_HI_REG_VALUE()	PV_READ_SS_HI_REG_VALUE()

#define	WRITE_CS_LO_REG_VALUE(sd)	PV_WRITE_CS_LO_REG_VALUE(sd)
#define	WRITE_CS_HI_REG_VALUE(sd)	PV_WRITE_CS_HI_REG_VALUE(sd)
#define	WRITE_DS_LO_REG_VALUE(sd)	PV_WRITE_DS_LO_REG_VALUE(sd)
#define	WRITE_DS_HI_REG_VALUE(sd)	PV_WRITE_DS_HI_REG_VALUE(sd)
#define	WRITE_ES_LO_REG_VALUE(sd)	PV_WRITE_ES_LO_REG_VALUE(sd)
#define	WRITE_ES_HI_REG_VALUE(sd)	PV_WRITE_ES_HI_REG_VALUE(sd)
#define	WRITE_FS_LO_REG_VALUE(sd)	PV_WRITE_FS_LO_REG_VALUE(sd)
#define	WRITE_FS_HI_REG_VALUE(sd)	PV_WRITE_FS_HI_REG_VALUE(sd)
#define	WRITE_GS_LO_REG_VALUE(sd)	PV_WRITE_GS_LO_REG_VALUE(sd)
#define	WRITE_GS_HI_REG_VALUE(sd)	PV_WRITE_GS_HI_REG_VALUE(sd)
#define	WRITE_SS_LO_REG_VALUE(sd)	PV_WRITE_SS_LO_REG_VALUE(sd)
#define	WRITE_SS_HI_REG_VALUE(sd)	PV_WRITE_SS_HI_REG_VALUE(sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	READ_IDR_REG_VALUE()		PV_READ_IDR_REG_VALUE()
#define	BOOT_READ_IDR_REG_VALUE()	BOOT_PV_READ_IDR_REG_VALUE()

/*
 * Processor Core Mode Register (CORE_MODE) and
 */
#define	READ_CORE_MODE_REG_VALUE()	PV_READ_CORE_MODE_REG_VALUE()
#define	BOOT_READ_CORE_MODE_REG_VALUE()	BOOT_PV_READ_CORE_MODE_REG_VALUE()
#define	WRITE_CORE_MODE_REG_VALUE(modes)	\
		PV_WRITE_CORE_MODE_REG_VALUE(modes)
#define	BOOT_WRITE_CORE_MODE_REG_VALUE(modes)	\
		BOOT_PV_WRITE_CORE_MODE_REG_VALUE(modes)

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! __ASSEMBLY__ */

#endif	/* __KERNEL__ */

#endif	/* _E2K_PARAVIRT_CPU_REGS_ACCESS_H_ */
