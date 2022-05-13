#ifndef	_E2K_KVM_CPU_REGS_ACCESS_H_
#define	_E2K_KVM_CPU_REGS_ACCESS_H_

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/kernel.h>

#include <asm/cpu_regs_types.h>

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>
#include <asm/glob_regs.h>
#include <asm/kvm/hypervisor.h>
#include <asm/kvm/hypercall.h>

/*
 * Basic macroses to access to virtual CPUs registers status on guest.
 */
#define	GUEST_CPU_REGS_STATUS	(offsetof(kvm_vcpu_state_t, cpu) +	\
				offsetof(kvm_cpu_state_t, regs_status))
#define	KVM_GET_CPU_REGS_STATUS()					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_CPU_REGS_STATUS)
#define	KVM_PUT_CPU_REGS_STATUS(status)					\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_CPU_REGS_STATUS, status)
#define	KVM_RESET_CPU_REGS_STATUS()					\
		KVM_SET_CPU_REGS_STATUS(0)
#define	KVM_PUT_UPDATED_CPU_REGS_FLAGS(flags)				\
({									\
	unsigned long regs_status = KVM_GET_CPU_REGS_STATUS();		\
	regs_status = KVM_SET_UPDATED_CPU_REGS_FLAGS(regs_status, flags); \
	KVM_PUT_CPU_REGS_STATUS(regs_status);				\
})
#define	KVM_RESET_UPDATED_CPU_REGS_FLAGS(flags)				\
({									\
	unsigned long regs_status = KVM_GET_CPU_REGS_STATUS();		\
	regs_status = KVM_INIT_UPDATED_CPU_REGS_FLAGS(regs_status);	\
	KVM_PUT_CPU_REGS_STATUS(regs_status);				\
})

/*
 * Basic functions accessing virtual CPUs registers on guest.
 */
#define	GUEST_CPU_SREGS_BASE	(offsetof(kvm_vcpu_state_t, cpu) +	\
				offsetof(kvm_cpu_state_t, regs))
#define	GUEST_CPU_SREG(reg_name) (GUEST_CPU_SREGS_BASE +		\
				(offsetof(kvm_cpu_regs_t, CPU_##reg_name)))
#define	GUEST_CPU_TIR_lo(TIR_no) (GUEST_CPU_SREGS_BASE +		\
				(offsetof(kvm_cpu_regs_t, CPU_TIRs)) +	\
				(sizeof(e2k_tir_t) * TIR_no) +		\
				(offsetof(e2k_tir_t, TIR_lo)))
#define	GUEST_CPU_TIR_hi(TIR_no) (GUEST_CPU_SREGS_BASE +		\
				(offsetof(kvm_cpu_regs_t, CPU_TIRs)) +	\
				(sizeof(e2k_tir_t) * TIR_no) +		\
				(offsetof(e2k_tir_t, TIR_hi)))
#define	GUEST_CPU_SBBP(SBBP_no) (GUEST_CPU_SREGS_BASE +		\
				(offsetof(kvm_cpu_regs_t, CPU_SBBP)) +	\
				(sizeof(u64) * SBBP_no))
#define	GUEST_GET_CPU_SREG(reg_name)					\
		E2K_LOAD_GUEST_VCPU_STATE_W(GUEST_CPU_SREG(reg_name))
#define	GUEST_GET_CPU_DSREG(reg_name)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_CPU_SREG(reg_name))
#define	GUEST_SET_CPU_SREG(reg_name, value)				\
		E2K_STORE_GUEST_VCPU_STATE_W(GUEST_CPU_SREG(reg_name), value)
#define	GUEST_SET_CPU_DSREG(reg_name, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_CPU_SREG(reg_name), value)
#define	GUEST_GET_CPU_TIR_lo(TIR_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_CPU_TIR_lo(TIR_no))
#define	GUEST_GET_CPU_TIR_hi(TIR_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_CPU_TIR_hi(TIR_no))
#define	GUEST_GET_CPU_SBBP(SBBP_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_CPU_SBBP(SBBP_no))
#define	GUEST_IRQS_UNDER_UPSR()	\
		offsetof(kvm_vcpu_state_t, irqs_under_upsr)

/*
 * Read virtual VCPU register with VCPU #
 */
#define KVM_READ_VCPU_ID()	((u32)GUEST_GET_CPU_SREG(VCPU_ID))

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define KVM_READ_PSHTP_REG_VALUE()	GUEST_GET_CPU_DSREG(PSHTP)
#define KVM_COPY_WRITE_PSHTP_REG_VALUE(PSHTP_value)	\
		GUEST_SET_CPU_DSREG(PSHTP, PSHTP_value)
#define KVM_WRITE_PSHTP_REG_VALUE(PSHTP_value) \
({ \
	KVM_COPY_WRITE_PSHTP_REG_VALUE(PSHTP_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_PSHTP_REG_VALUE(PSHTP_value); \
})

#define KVM_NV_READ_PSHTP_REG_VALUE	KVM_READ_PSHTP_REG_VALUE
#define	KVM_READ_PSHTP_REG()	\
({ \
	e2k_pshtp_t	PSHTP; \
	PSHTP.PSHTP_reg = KVM_READ_PSHTP_REG_VALUE(); \
	PSHTP; \
})

/*
 * Read/write word Procedure Chain Stack Hardware Top Pointer (PCSHTP)
 */
#define KVM_READ_PCSHTP_REG_SVALUE()				\
		(((e2k_pcshtp_t)GUEST_GET_CPU_SREG(PCSHTP) <<	\
				(32 - E2K_PCSHTP_SIZE)) >>	\
					(32 - E2K_PCSHTP_SIZE))
#define KVM_COPY_WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)	\
		GUEST_SET_CPU_DSREG(PCSHTP, PCSHTP_svalue)
#define KVM_WRITE_PCSHTP_REG_SVALUE(PCSHTP_value) \
({ \
	KVM_COPY_WRITE_PCSHTP_REG_SVALUE(PCSHTP_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_PCSHTP_REG_SVALUE(PCSHTP_value); \
})

#define	KVM_READ_PCSHTP_REG()	\
({ \
	e2k_pcshtp_t	PCSHTP; \
	PCSHTP = KVM_READ_PCSHTP_REG_SVALUE(); \
	PCSHTP; \
})

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

#define KVM_READ_OSCUD_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(OSCUD_lo)
#define KVM_READ_OSCUD_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(OSCUD_hi)
#define BOOT_KVM_READ_OSCUD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(OSCUD_lo)
#define BOOT_KVM_READ_OSCUD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(OSCUD_hi)

#define KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
		GUEST_SET_CPU_DSREG(OSCUD_lo, OSCUD_lo_value)
#define KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
		GUEST_SET_CPU_DSREG(OSCUD_hi, OSCUD_hi_value);
#define KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
({ \
	KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
({ \
	KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
})

#define BOOT_KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
		GUEST_SET_CPU_DSREG(OSCUD_lo, OSCUD_lo_value)
#define BOOT_KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
		GUEST_SET_CPU_DSREG(OSCUD_hi, OSCUD_hi_value);
#define BOOT_KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value) \
({ \
	BOOT_KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define BOOT_KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value) \
({ \
	BOOT_KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
})

#define	KVM_COPY_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	KVM_COPYWRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	KVM_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	KVM_WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	KVM_WRITE_OSCUD_REG_VALUE(OSCUD_hi_value, OSCUD_lo_value) \
({ \
	KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value); \
	KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value); \
})
#define	KVM_WRITE_OSCUD_REG(OSCUD_hi, OSCUD_lo) \
({ \
	KVM_WRITE_OSCUD_REG_VALUE(OSCUD_hi.OSCUD_hi_half, \
					OSCUD_lo.OSCUD_lo_half); \
})

#define	BOOT_KVM_COPY_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	BOOT_KVM_COPY_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	BOOT_KVM_COPYWRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	BOOT_KVM_COPY_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})
#define	BOOT_KVM_WRITE_OSCUD_LO_REG(OSCUD_lo) \
({ \
	BOOT_KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo.OSCUD_lo_half); \
})
#define	BOOT_KVM_WRITE_OSCUD_HI_REG(OSCUD_hi) \
({ \
	BOOT_KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi.OSCUD_hi_half); \
})

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define KVM_READ_OSGD_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(OSGD_lo)
#define KVM_READ_OSGD_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(OSGD_hi)
#define BOOT_KVM_READ_OSGD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(OSGD_lo)
#define BOOT_KVM_READ_OSGD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(OSGD_hi)

#define KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
		GUEST_SET_CPU_DSREG(OSGD_lo, OSGD_lo_value)
#define KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
		GUEST_SET_CPU_DSREG(OSGD_hi, OSGD_hi_value)
#define BOOT_KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
		GUEST_SET_CPU_DSREG(OSGD_lo, OSGD_lo_value)
#define BOOT_KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
		GUEST_SET_CPU_DSREG(OSGD_hi, OSGD_hi_value)

#define KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
({ \
	KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
({ \
	KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
})
#define BOOT_KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value) \
({ \
	BOOT_KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
})
#define BOOT_KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value) \
({ \
	BOOT_KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
})

#define	KVM_COPY_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	KVM_COPY_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	KVM_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	KVM_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})

#define	BOOT_KVM_COPY_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	BOOT_KVM_COPY_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	BOOT_KVM_COPY_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	BOOT_KVM_COPY_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})
#define	BOOT_KVM_WRITE_OSGD_LO_REG(OSGD_lo) \
({ \
	BOOT_KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo.OSGD_lo_half); \
})
#define	BOOT_KVM_WRITE_OSGD_HI_REG(OSGD_hi) \
({ \
	BOOT_KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi.OSGD_hi_half); \
})

/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */

#define KVM_READ_CUD_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(CUD_lo)
#define KVM_READ_CUD_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(CUD_hi)
#define BOOT_KVM_READ_CUD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(CUD_lo)
#define BOOT_KVM_READ_CUD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(CUD_hi)

#define KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo_value) \
({ \
	GUEST_SET_CPU_DSREG(CUD_lo, CUD_lo_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi_value) \
({ \
	GUEST_SET_CPU_DSREG(CUD_hi, CUD_hi_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
})

#define BOOT_KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo_value) \
({ \
	GUEST_SET_CPU_DSREG(CUD_lo, CUD_lo_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define BOOT_KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi_value) \
({ \
	GUEST_SET_CPU_DSREG(CUD_hi, CUD_hi_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
})

#define	KVM_WRITE_CUD_LO_REG(CUD_lo) \
({ \
	KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo.CUD_lo_half); \
})
#define	KVM_WRITE_CUD_HI_REG(CUD_hi) \
({ \
	KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi.CUD_hi_half); \
})
#define	KVM_WRITE_CUD_REG_VALUE(CUD_hi_value, CUD_lo_value) \
({ \
	KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi_value); \
	KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo_value); \
})
#define	KVM_WRITE_CUD_REG(CUD_hi, CUD_lo) \
({ \
	KVM_WRITE_CUD_REG_VALUE(CUD_hi.CUD_hi_half, CUD_lo.CUD_lo_half); \
})

#define	BOOT_KVM_WRITE_CUD_LO_REG(CUD_lo) \
({ \
	BOOT_KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo.CUD_lo_half); \
})
#define	BOOT_KVM_WRITE_CUD_HI_REG(CUD_hi) \
({ \
	BOOT_KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi.CUD_hi_half); \
})

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define KVM_READ_GD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(GD_lo)
#define KVM_READ_GD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(GD_hi)
#define BOOT_KVM_READ_GD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(GD_lo)
#define BOOT_KVM_READ_GD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(GD_hi)

#define KVM_WRITE_GD_LO_REG_VALUE(GD_lo_value) \
({ \
	GUEST_SET_CPU_DSREG(GD_lo, GD_lo_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#define KVM_WRITE_GD_HI_REG_VALUE(GD_hi_value) \
({ \
	GUEST_SET_CPU_DSREG(GD_hi, GD_hi_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value); \
})

#define BOOT_KVM_WRITE_GD_LO_REG_VALUE(GD_lo_value) \
({ \
	GUEST_SET_CPU_DSREG(GD_lo, GD_lo_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_GD_LO_REG_VALUE(GD_lo_value); \
})
#define BOOT_KVM_WRITE_GD_HI_REG_VALUE(GD_hi_value) \
({ \
	GUEST_SET_CPU_DSREG(GD_hi, GD_hi_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_GD_HI_REG_VALUE(GD_hi_value); \
})
#define	KVM_WRITE_GD_LO_REG(GD_lo) \
({ \
	KVM_WRITE_GD_LO_REG_VALUE(GD_lo.GD_lo_half); \
})
#define	KVM_WRITE_GD_HI_REG(GD_hi) \
({ \
	KVM_WRITE_GD_HI_REG_VALUE(GD_hi.GD_hi_half); \
})
#define	BOOT_KVM_WRITE_GD_LO_REG(GD_lo) \
({ \
	BOOT_KVM_WRITE_GD_LO_REG_VALUE(GD_lo.GD_lo_half); \
})
#define	BOOT_KVM_WRITE_GD_HI_REG(GD_hi) \
({ \
	BOOT_KVM_WRITE_GD_HI_REG_VALUE(GD_hi.GD_hi_half); \
})

/*
 * Read/write double-word Compilation Unit Table Register (CUTD/OSCUTD)
 */
#define KVM_READ_CUTD_REG_VALUE()		GUEST_GET_CPU_DSREG(CUTD)
#define KVM_READ_OSCUTD_REG_VALUE()		GUEST_GET_CPU_DSREG(OSCUTD)
#define BOOT_KVM_READ_CUTD_REG_VALUE()		GUEST_GET_CPU_DSREG(CUTD)
#define BOOT_KVM_READ_OSCUTD_REG_VALUE()	GUEST_GET_CPU_DSREG(OSCUTD)

#define KVM_WRITE_CUTD_REG_VALUE(CUTD_value)	\
({ \
	GUEST_SET_CPU_DSREG(CUTD, CUTD_value); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD_value); \
})
#define KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
		GUEST_SET_CPU_DSREG(OSCUTD, CUTD_value)
#define KVM_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
({ \
	KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD_value); \
	if (IS_HV_GM()) \
		native_write_OSCUTD_reg_value(CUTD_value); \
})
#define BOOT_KVM_WRITE_CUTD_REG_VALUE(CUTD_value)	\
({ \
	GUEST_SET_CPU_DSREG(CUTD, CUTD_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(CUTD_value); \
})
#define BOOT_KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
		GUEST_SET_CPU_DSREG(OSCUTD, CUTD_value)
#define BOOT_KVM_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
({ \
	BOOT_KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD_value); \
	if (IS_HV_GM()) \
		boot_native_write_OSCUTD_reg_value(CUTD_value); \
})

#define	KVM_WRITE_CUTD_REG(CUTD)	\
		KVM_WRITE_CUTD_REG_VALUE(CUTD.CUTD_reg)
#define	KVM_COPY_WRITE_OSCUTD_REG(CUTD)	\
		KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD.CUTD_reg)
#define	KVM_WRITE_OSCUTD_REG(CUTD)	\
		KVM_WRITE_OSCUTD_REG_VALUE(CUTD.CUTD_reg)
#define	BOOT_KVM_WRITE_CUTD_REG(CUTD)	\
		BOOT_KVM_WRITE_CUTD_REG_VALUE(CUTD.CUTD_reg)
#define	BOOT_KVM_COPY_WRITE_OSCUTD_REG(CUTD)	\
		BOOT_KVM_COPY_WRITE_OSCUTD_REG_VALUE(CUTD.CUTD_reg)
#define	BOOT_KVM_WRITE_OSCUTD_REG(CUTD)	\
		BOOT_KVM_WRITE_OSCUTD_REG_VALUE(CUTD.CUTD_reg)

/*
 * Read word Compilation Unit Index Register (CUIR/OSCUIR)
 */
#define KVM_READ_CUIR_REG_VALUE()		GUEST_GET_CPU_SREG(CUIR)
#define KVM_READ_OSCUIR_REG_VALUE()		GUEST_GET_CPU_SREG(OSCUIR)
#define BOOT_KVM_READ_CUIR_REG_VALUE()		GUEST_GET_CPU_SREG(CUIR)
#define BOOT_KVM_READ_OSCUIR_REG_VALUE()	GUEST_GET_CPU_SREG(OSCUIR)

#define KVM_COPY_WRITE_OSCUIR_REG_VALUE(v)	GUEST_SET_CPU_SREG(OSCUIR, (v))
#define KVM_WRITE_OSCUIR_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_OSCUIR_REG_VALUE(v); \
	if (IS_HV_GM()) \
		native_write_OSCUIR_reg_value((v)); \
})
#define BOOT_KVM_COPY_WRITE_OSCUIR_REG_VALUE(v)	GUEST_SET_CPU_SREG(OSCUIR, (v))
#define BOOT_KVM_WRITE_OSCUIR_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_OSCUIR_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		boot_native_write_OSCUIR_reg_value((v)); \
})

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define KVM_READ_PSP_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(PSP_lo)
#define KVM_READ_PSP_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(PSP_hi)
#define KVM_COPY_WRITE_PSP_LO_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PSP_lo, v)
#define KVM_COPY_WRITE_PSP_HI_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PSP_hi, v)
#define KVM_WRITE_PSP_LO_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_PSP_LO_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE((v)); \
})
#define KVM_WRITE_PSP_HI_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_PSP_HI_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(v); \
})

#define KVM_NV_READ_PSP_LO_REG_VALUE	KVM_READ_PSP_LO_REG_VALUE
#define KVM_NV_READ_PSP_HI_REG_VALUE	KVM_READ_PSP_HI_REG_VALUE
#define	KVM_READ_PSP_LO_REG() \
({ \
	e2k_psp_lo_t	PSP_lo; \
	PSP_lo.PSP_lo_half = KVM_READ_PSP_LO_REG_VALUE(); \
	PSP_lo; \
})
#define	KVM_READ_PSP_HI_REG() \
({ \
	e2k_psp_hi_t	PSP_hi; \
	PSP_hi.PSP_hi_half = KVM_READ_PSP_HI_REG_VALUE(); \
	PSP_hi; \
})

#define KVM_NV_WRITE_PSP_REG_VALUE	KVM_WRITE_PSP_REG_VALUE
#define	KVM_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	KVM_WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	KVM_WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	KVM_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	KVM_WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})

#define BOOT_KVM_READ_PSP_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(PSP_lo)
#define BOOT_KVM_READ_PSP_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(PSP_hi)
#define BOOT_KVM_COPY_WRITE_PSP_LO_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PSP_lo, v)
#define BOOT_KVM_COPY_WRITE_PSP_HI_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PSP_hi, v)
#define BOOT_KVM_WRITE_PSP_LO_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_PSP_LO_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_WRITE_PSP_LO_REG_VALUE((v)); \
})
#define BOOT_KVM_WRITE_PSP_HI_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_PSP_HI_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_PSP_HI_REG_VALUE(v); \
})
#define	BOOT_KVM_WRITE_PSP_REG_VALUE(PSP_hi_value, PSP_lo_value) \
({ \
	BOOT_KVM_WRITE_PSP_HI_REG_VALUE(PSP_hi_value); \
	BOOT_KVM_WRITE_PSP_LO_REG_VALUE(PSP_lo_value); \
})
#define	BOOT_KVM_WRITE_PSP_REG(PSP_hi, PSP_lo) \
({ \
	BOOT_KVM_WRITE_PSP_REG_VALUE(PSP_hi.PSP_hi_half, PSP_lo.PSP_lo_half); \
})

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define KVM_READ_PCSP_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(PCSP_lo)
#define KVM_READ_PCSP_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(PCSP_hi)
#define KVM_COPY_WRITE_PCSP_LO_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PCSP_lo, v)
#define KVM_COPY_WRITE_PCSP_HI_REG_VALUE(v)	GUEST_SET_CPU_DSREG(PCSP_hi, v)
#define KVM_WRITE_PCSP_LO_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_PCSP_LO_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(v); \
})
#define KVM_WRITE_PCSP_HI_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_PCSP_HI_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(v); \
})

#define KVM_NV_READ_PCSP_LO_REG_VALUE	KVM_READ_PCSP_LO_REG_VALUE
#define KVM_NV_READ_PCSP_HI_REG_VALUE	KVM_READ_PCSP_HI_REG_VALUE
#define	KVM_READ_PCSP_LO_REG() \
({ \
	e2k_pcsp_lo_t	PCSP_lo; \
	PCSP_lo.PCSP_lo_half = KVM_READ_PCSP_LO_REG_VALUE(); \
	PCSP_lo; \
})
#define	KVM_READ_PCSP_HI_REG() \
({ \
	e2k_pcsp_hi_t	PCSP_hi; \
	PCSP_hi.PCSP_hi_half = KVM_READ_PCSP_HI_REG_VALUE(); \
	PCSP_hi; \
})

#define	KVM_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value) \
({ \
	KVM_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value); \
	KVM_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value); \
})
#define	KVM_NV_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value)	\
		KVM_WRITE_PCSP_REG_VALUE(PCSP_hi_value, PCSP_lo_value)
#define	KVM_WRITE_PCSP_REG(PCSP_hi, PCSP_lo) \
({ \
	KVM_WRITE_PCSP_REG_VALUE(PCSP_hi.PCSP_hi_half, PCSP_lo.PCSP_lo_half); \
})

#define BOOT_KVM_READ_PCSP_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(PCSP_lo)
#define BOOT_KVM_READ_PCSP_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(PCSP_hi)
#define BOOT_KVM_COPY_WRITE_PCSP_LO_REG_VALUE(v)	\
		GUEST_SET_CPU_DSREG(PCSP_lo, v)
#define BOOT_KVM_COPY_WRITE_PCSP_HI_REG_VALUE(v)	\
		GUEST_SET_CPU_DSREG(PCSP_hi, v)
#define BOOT_KVM_WRITE_PCSP_LO_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_PCSP_LO_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_WRITE_PCSP_LO_REG_VALUE(v); \
})
#define BOOT_KVM_WRITE_PCSP_HI_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_PCSP_HI_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_PCSP_HI_REG_VALUE(v); \
})
#define	BOOT_KVM_WRITE_PCSP_REG_VALUE(hi_value, lo_value) \
({ \
	BOOT_KVM_WRITE_PCSP_HI_REG_VALUE(hi_value); \
	BOOT_KVM_WRITE_PCSP_LO_REG_VALUE(lo_value); \
})
#define	BOOT_KVM_WRITE_PCSP_REG(hi, lo) \
({ \
	BOOT_KVM_WRITE_PCSP_REG_VALUE(hi.PCSP_hi_half, lo.PCSP_lo_half); \
})

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define KVM_COPY_READ_CR0_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(CR0_lo)
#define KVM_COPY_READ_CR0_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(CR0_hi)
#define KVM_COPY_READ_CR1_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(CR1_lo)
#define KVM_COPY_READ_CR1_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(CR1_hi)
#define KVM_READ_CR0_LO_REG_VALUE()	\
({ \
	((IS_HV_GM()) ? NATIVE_NV_READ_CR0_LO_REG_VALUE() \
			: \
			KVM_COPY_READ_CR0_LO_REG_VALUE()); \
})
#define KVM_READ_CR0_HI_REG_VALUE()	\
({ \
	((IS_HV_GM()) ? NATIVE_NV_READ_CR0_HI_REG_VALUE() \
			: \
			KVM_COPY_READ_CR0_HI_REG_VALUE()); \
})
#define KVM_READ_CR1_LO_REG_VALUE()	\
({ \
	((IS_HV_GM()) ? NATIVE_NV_READ_CR1_LO_REG_VALUE() \
			: \
			KVM_COPY_READ_CR1_LO_REG_VALUE()); \
})
#define KVM_READ_CR1_HI_REG_VALUE()	\
({ \
	((IS_HV_GM()) ? NATIVE_NV_READ_CR1_HI_REG_VALUE() \
			: \
			KVM_COPY_READ_CR1_HI_REG_VALUE()); \
})

#define KVM_COPY_WRITE_CR0_LO_REG_VALUE(CR0_lo_value) \
		GUEST_SET_CPU_DSREG(CR0_lo, CR0_lo_value)
#define KVM_COPY_WRITE_CR0_HI_REG_VALUE(CR0_hi_value) \
		GUEST_SET_CPU_DSREG(CR0_hi, CR0_hi_value)
#define KVM_COPY_WRITE_CR1_LO_REG_VALUE(CR1_lo_value) \
		GUEST_SET_CPU_DSREG(CR1_lo, CR1_lo_value)
#define KVM_COPY_WRITE_CR1_HI_REG_VALUE(CR1_hi_value) \
		GUEST_SET_CPU_DSREG(CR1_hi, CR1_hi_value)
#define KVM_WRITE_CR0_LO_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_CR0_LO_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(v); \
})
#define KVM_WRITE_CR0_HI_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_CR0_HI_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(v); \
})
#define KVM_WRITE_CR1_LO_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_CR1_LO_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(v); \
})
#define KVM_WRITE_CR1_HI_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_CR1_HI_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(v); \
})

#define	KVM_NV_READ_CR0_LO_REG_VALUE()	KVM_READ_CR0_LO_REG_VALUE()
#define	KVM_NV_READ_CR0_HI_REG_VALUE()	KVM_READ_CR0_HI_REG_VALUE()
#define	KVM_NV_READ_CR1_LO_REG_VALUE()	KVM_READ_CR1_LO_REG_VALUE()
#define	KVM_NV_READ_CR1_HI_REG_VALUE()	KVM_READ_CR1_HI_REG_VALUE()

#define	KVM_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)	\
			KVM_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)
#define	KVM_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)	\
			KVM_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)
#define	KVM_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)	\
			KVM_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)
#define	KVM_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)	\
			KVM_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */
#define	KVM_READ_CTPR_REG_VALUE(reg_no)	GUEST_GET_CPU_DSREG(CTPR##reg_no)
#define	KVM_READ_CTPR1_REG_VALUE()	KVM_READ_CTPR_REG_VALUE(1)
#define	KVM_READ_CTPR2_REG_VALUE()	KVM_READ_CTPR_REG_VALUE(2)
#define	KVM_READ_CTPR3_REG_VALUE()	KVM_READ_CTPR_REG_VALUE(3)

#define	KVM_WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)	\
		GUEST_SET_CPU_DSREG(CTPR##reg_no, CTPR_value)
#define	KVM_WRITE_CTPR1_REG_VALUE(CTPR_value)		\
		KVM_WRITE_CTPR_REG_VALUE(1, CTPR_value)
#define	KVM_WRITE_CTPR2_REG_VALUE(CTPR_value)		\
		KVM_WRITE_CTPR_REG_VALUE(2, CTPR_value)
#define	KVM_WRITE_CTPR3_REG_VALUE(CTPR_value)		\
		KVM_WRITE_CTPR_REG_VALUE(3, CTPR_value)

/*
 * Read/write low/high double-word Trap Info Registers (TIRs)
 */
#define	KVM_READ_TIRs_num()	GUEST_GET_CPU_SREG(TIRs_num)
#define	KVM_WRITE_TIRs_num(TIRs_num_value)				\
		GUEST_SET_CPU_SREG(TIRs_num, TIRs_num_value)
#define	KVM_READ_TIR_HI_REG_VALUE()					\
({									\
	unsigned long TIR_hi_value;					\
	int TIRs_num;							\
	TIRs_num = KVM_READ_TIRs_num();					\
	if (TIRs_num >= 0) {						\
		TIR_hi_value = GUEST_GET_CPU_TIR_hi(TIRs_num);		\
	} else {							\
		TIR_hi_value = 0;					\
	}								\
	TIR_hi_value;							\
})
#define	KVM_READ_TIR_LO_REG_VALUE()					\
({									\
	unsigned long TIR_lo_value;					\
	int TIRs_num;							\
	TIRs_num = KVM_READ_TIRs_num();					\
	if (TIRs_num >= 0) {						\
		TIR_lo_value = GUEST_GET_CPU_TIR_lo(TIRs_num);		\
		TIRs_num--;						\
		KVM_WRITE_TIRs_num(TIRs_num);				\
	} else {							\
		TIR_lo_value = 0;					\
	}								\
	TIR_lo_value;							\
})

#define	KVM_WRITE_TIR_LO_REG_VALUE(TIR_lo_value)			\
		KVM_WRITE_TIRs_num(-1)
#define	KVM_WRITE_TIR_HI_REG_VALUE(TIR_hi_value)			\
		KVM_WRITE_TIRs_num(-1)

/*
 * Read double-word Stcak of Base Blocks Pointers (SBBP)
 */
#define	KVM_READ_SBBP_REG_VALUE(no)	GUEST_GET_CPU_SBBP(no)

/*
 * Read/write virtual deferred traps register - DTR
 */
#define	KVM_READ_DTR_REG_VALUE()	GUEST_GET_CPU_DSREG(DTR)

#define	KVM_WRITE_DTR_REG_VALUE(DTR_value)	\
		GUEST_SET_CPU_DSREG(DTR, DTR_value)

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define KVM_READ_USD_LO_REG_VALUE()		GUEST_GET_CPU_DSREG(USD_lo)
#define KVM_READ_USD_HI_REG_VALUE()		GUEST_GET_CPU_DSREG(USD_hi)
#define KVM_COPY_WRITE_USD_LO_REG_VALUE(v)	GUEST_SET_CPU_DSREG(USD_lo, v)
#define KVM_COPY_WRITE_USD_HI_REG_VALUE(v)	GUEST_SET_CPU_DSREG(USD_hi, v)
#define KVM_WRITE_USD_LO_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_USD_LO_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(v); \
})
#define KVM_WRITE_USD_HI_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_USD_HI_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(v); \
})

#define	KVM_NV_WRITE_USD_LO_REG_VALUE(USD_lo_value) \
		KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	KVM_NV_WRITE_USD_HI_REG_VALUE(USD_hi_value) \
		KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value)
#define	KVM_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	KVM_NV_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
		KVM_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value)
#define	KVM_WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	KVM_WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})

#define	KVM_WRITE_USBR_USD_REG_VALUE(usbr, USD_hi_value, USD_lo_value) \
({ \
	KVM_WRITE_USBR_REG_VALUE(usbr); \
	KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	KVM_NV_WRITE_USBR_USD_REG_VALUE(usbr, USD_hi_value, USD_lo_value) \
		KVM_WRITE_USBR_USD_REG_VALUE(usbr, USD_hi_value, USD_lo_value)

#define BOOT_KVM_READ_USD_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(USD_lo)
#define BOOT_KVM_READ_USD_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(USD_hi)
#define BOOT_KVM_COPY_WRITE_USD_LO_REG_VALUE(v)	GUEST_SET_CPU_DSREG(USD_lo, v)
#define BOOT_KVM_COPY_WRITE_USD_HI_REG_VALUE(v)	GUEST_SET_CPU_DSREG(USD_hi, v)
#define BOOT_KVM_WRITE_USD_LO_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_USD_LO_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_WRITE_USD_LO_REG_VALUE(v); \
})
#define BOOT_KVM_WRITE_USD_HI_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_USD_HI_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_WRITE_USD_HI_REG_VALUE(v); \
})
#define	BOOT_KVM_WRITE_USD_REG_VALUE(USD_hi_value, USD_lo_value) \
({ \
	BOOT_KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	BOOT_KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})
#define	BOOT_KVM_WRITE_USD_REG(USD_hi, USD_lo) \
({ \
	BOOT_KVM_WRITE_USD_REG_VALUE(USD_hi.USD_hi_half, USD_lo.USD_lo_half); \
})
#define	BOOT_KVM_WRITE_USBR_USD_REG_VALUE(usbr, USD_hi_value, USD_lo_value) \
({ \
	BOOT_KVM_WRITE_USBR_REG_VALUE(usbr); \
	BOOT_KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value); \
	BOOT_KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value); \
})

/*
 * Read/write low/high double-word Protected User Stack Descriptor
 * Register (PUSD)
 */
#define	KVM_READ_PUSD_LO_REG_VALUE()	KVM_READ_USD_LO_REG_VALUE()
#define	KVM_READ_PUSD_HI_REG_VALUE()	KVM_READ_USD_HI_REG_VALUE()

#define	KVM_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value) \
		KVM_WRITE_USD_LO_REG_VALUE(PUSD_lo_value)
#define	KVM_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value) \
		KVM_WRITE_USD_HI_REG_VALUE(PUSD_hi_value)

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define KVM_READ_SBR_REG_VALUE()	GUEST_GET_CPU_DSREG(SBR)
#define KVM_COPY_WRITE_SBR_REG_VALUE(v)	GUEST_SET_CPU_DSREG(SBR, v)
#define KVM_WRITE_SBR_REG_VALUE(v)	\
({ \
	KVM_COPY_WRITE_SBR_REG_VALUE(v); \
	if (IS_HV_GM()) \
		NATIVE_NV_WRITE_SBR_REG_VALUE(v); \
})

#define	KVM_READ_USBR_REG_VALUE()	KVM_READ_SBR_REG_VALUE()
#define	KVM_NV_READ_SBR_REG_VALUE()	KVM_READ_SBR_REG_VALUE()

#define	KVM_WRITE_USBR_REG_VALUE(USBR_value) KVM_WRITE_SBR_REG_VALUE(USBR_value)
#define	KVM_NV_WRITE_SBR_REG_VALUE(SBR_value) KVM_WRITE_SBR_REG_VALUE(SBR_value)
#define	KVM_WRITE_USBR_REG(USBR)	\
		KVM_WRITE_USBR_REG_VALUE(USBR.USBR_reg)

#define BOOT_KVM_READ_SBR_REG_VALUE()		GUEST_GET_CPU_DSREG(SBR)
#define BOOT_KVM_COPY_WRITE_SBR_REG_VALUE(v)	GUEST_SET_CPU_DSREG(SBR, v)
#define BOOT_KVM_WRITE_SBR_REG_VALUE(v)	\
({ \
	BOOT_KVM_COPY_WRITE_SBR_REG_VALUE(v); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_NV_WRITE_SBR_REG_VALUE(v); \
})

#define	BOOT_KVM_READ_USBR_REG_VALUE()	BOOT_KVM_READ_SBR_REG_VALUE()

#define	BOOT_KVM_WRITE_USBR_REG_VALUE(v)	\
		BOOT_KVM_WRITE_SBR_REG_VALUE(v)
#define	BOOT_KVM_WRITE_USBR_REG(USBR)	\
		BOOT_KVM_WRITE_USBR_REG_VALUE(USBR.USBR_reg)

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	KVM_READ_WD_REG_VALUE()		GUEST_GET_CPU_DSREG(WD)
#define	KVM_READ_WD_REG() \
({ \
	e2k_wd_t	WD; \
	WD.WD_reg = KVM_READ_WD_REG_VALUE(); \
	WD; \
})

#define	KVM_WRITE_WD_REG_VALUE(WD_value)	\
		GUEST_SET_CPU_DSREG(WD, WD_value)
#define	KVM_WRITE_WD_REG(WD)	\
		KVM_WRITE_WD_REG_VALUE(WD.WD_reg)

/*
 * Read/write double-word Loop Status Register (LSR)
 */
#define	KVM_READ_LSR_REG_VALUE()		GUEST_GET_CPU_DSREG(LSR)
#define	KVM_READ_LSR1_REG_VALUE()		GUEST_GET_CPU_DSREG(LSR1)

#define	KVM_WRITE_LSR_REG_VALUE(LSR_value)	\
		GUEST_SET_CPU_DSREG(LSR, LSR_value)

/*
 * Read/write double-word Initial Loop Counters Register (ILCR)
 */
#define	KVM_READ_ILCR_REG_VALUE()		GUEST_GET_CPU_DSREG(ILCR)
#define	KVM_READ_ILCR1_REG_VALUE()		GUEST_GET_CPU_DSREG(ILCR1)

#define	KVM_WRITE_ILCR_REG_VALUE(ILCR_value)	\
				GUEST_SET_CPU_DSREG(ILCR, ILCR_value)

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	KVM_GET_OSR0_REG_VALUE()	GUEST_GET_CPU_DSREG(OSR0)

#define	KVM_SET_OSR0_REG_VALUE(osr0_value)	\
		GUEST_SET_CPU_DSREG(OSR0, osr0_value)

#define	KVM_READ_CURRENT_REG_VALUE()	\
({ \
	unsigned long osr0_value; \
	if (IS_HV_GM()) { \
		osr0_value = NATIVE_GET_OSR0_REG_VALUE(); \
	} else { \
		osr0_value = KVM_GET_OSR0_REG_VALUE(); \
	} \
	osr0_value; \
})

#define	BOOT_KVM_READ_CURRENT_REG_VALUE()	KVM_GET_OSR0_REG_VALUE()
#define	KVM_WRITE_CURRENT_REG_VALUE(osr0_value)	\
({ \
	KVM_SET_OSR0_REG_VALUE(osr0_value); \
	if (IS_HV_CPU_HV_MMU_KVM()) { \
		NATIVE_SET_OSR0_REG_VALUE(osr0_value); \
	} \
})
#define	BOOT_KVM_WRITE_CURRENT_REG_VALUE(osr0_value)	\
({ \
	KVM_SET_OSR0_REG_VALUE(osr0_value); \
	if (IS_HV_CPU_HV_MMU_KVM()) { \
		NATIVE_SET_OSR0_REG_VALUE(osr0_value); \
	} \
})

#define	KVM_READ_CURRENT_REG() \
({ \
	struct thread_info *TI; \
	TI = (struct thread_info *)KVM_READ_CURRENT_REG_VALUE(); \
	TI; \
})
#define	BOOT_KVM_READ_CURRENT_REG() \
({ \
	struct thread_info *TI; \
	TI = (struct thread_info *)BOOT_KVM_READ_CURRENT_REG_VALUE(); \
	TI; \
})
#define	KVM_WRITE_CURRENT_REG(TI)	\
		KVM_WRITE_CURRENT_REG_VALUE((unsigned long)TI)
#define	BOOT_KVM_WRITE_CURRENT_REG(TI)	\
		BOOT_KVM_WRITE_CURRENT_REG_VALUE((unsigned long)TI)

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	KVM_READ_OSEM_REG_VALUE()		GUEST_GET_CPU_SREG(OSEM)

#define	KVM_WRITE_OSEM_REG_VALUE(OSEM_value)	\
		GUEST_SET_CPU_SREG(OSEM, OSEM_value)

/*
 * Read/write word Base Global Register (BGR)
 */
#define	KVM_READ_BGR_REG_VALUE()		GUEST_GET_CPU_SREG(BGR)

#define	KVM_WRITE_BGR_REG_VALUE(BGR_value)	\
		GUEST_SET_CPU_SREG(BGR, BGR_value)

#define	BOOT_KVM_WRITE_BGR_REG_VALUE(BGR_value)	\
({ \
	KVM_WRITE_BGR_REG_VALUE(BGR_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_BGR_REG_VALUE(BGR_value); \
})

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	KVM_READ_CLKR_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(clkr)

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	KVM_READ_SCLKR_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sclkr)
#define	KVM_READ_SCLKM1_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sclkm1)
#define	KVM_READ_SCLKM2_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sclkm2)
#define	KVM_READ_SCLKM3_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(sclkm3)

#define	KVM_WRITE_SCLKR_REG_VALUE(reg_value)	\
		GUEST_SET_CPU_DSREG(SCLKR, reg_value)
#define	KVM_WRITE_SCLKM1_REG_VALUE(reg_value)	\
		GUEST_SET_CPU_DSREG(SCLKM1, reg_value)
#define	KVM_WRITE_SCLKM2_REG_VALUE(reg_value)	\
		GUEST_SET_CPU_DSREG(SCLKM2, reg_value)
#define	KVM_WRITE_SCLKM3_REG_VALUE(reg_value)	\
		GUEST_SET_CPU_DSREG(SCLKM3, reg_value)

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	KVM_READ_CU_HW0_REG_VALUE()	NATIVE_READ_CU_HW0_REG_VALUE()
#define	KVM_READ_CU_HW1_REG_VALUE()	\
({ \
	u64 reg_value = -1; \
	if (machine.get_cu_hw1 != NULL) \
		reg_value = machine.get_cu_hw1(); \
	reg_value; \
})

#define	KVM_WRITE_CU_HW0_REG_VALUE(reg)	GUEST_SET_CPU_DSREG(CU_HW0, reg)
#define	KVM_WRITE_CU_HW1_REG_VALUE(reg)	GUEST_SET_CPU_DSREG(CU_HW1, reg)

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	KVM_READ_RPR_LO_REG_VALUE()	NATIVE_GET_DSREG_OPEN(rpr.lo)
#define	KVM_READ_RPR_HI_REG_VALUE()	NATIVE_GET_DSREG_OPEN(rpr.hi)

#define	KVM_WRITE_RPR_LO_REG_VALUE(RPR_lo_value) \
			NATIVE_SET_DSREG_OPEN(rpr.lo, RPR_lo_value)
#define	KVM_WRITE_RPR_HI_REG_VALUE(RPR_hi_value) \
			NATIVE_SET_DSREG_OPEN(rpr.hi, RPR_hi_value)

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	KVM_READ_IP_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(ip)

/*
 * Read debug and monitors registers
 */
#define	KVM_READ_DIBCR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(dibcr)
#define	KVM_READ_DIBSR_REG_VALUE()	NATIVE_GET_SREG_CLOSED(dibsr)
#define	KVM_READ_DIMCR_REG_VALUE()	NATIVE_GET_DSREG_CLOSED(dimcr)
#define	KVM_READ_DIBAR0_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar0)
#define	KVM_READ_DIBAR1_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar1)
#define	KVM_READ_DIBAR2_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar2)
#define	KVM_READ_DIBAR3_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dibar3)
#define	KVM_READ_DIMAR0_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dimar0)
#define	KVM_READ_DIMAR1_REG_VALUE()	NATIVE_GET_DSREG_OPEN(dimar1)

#define	KVM_WRITE_DIBCR_REG_VALUE(DIBCR_value)	\
			GUEST_SET_CPU_SREG(DIBCR, DIBCR_value)
#define	KVM_WRITE_DIBSR_REG_VALUE(DIBSR_value)	\
			NATIVE_SET_SREG_CLOSED_NOEXC(dibsr, DIBSR_value, 4)
#define	KVM_WRITE_DIMCR_REG_VALUE(DIMCR_value)	\
			GUEST_SET_CPU_DSREG(DIMCR, DIMCR_value)
#define	KVM_WRITE_DIBAR0_REG_VALUE(DIBAR0_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dibar0, DIBAR0_value, 4)
#define	KVM_WRITE_DIBAR1_REG_VALUE(DIBAR1_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dibar1, DIBAR1_value, 4)
#define	KVM_WRITE_DIBAR2_REG_VALUE(DIBAR2_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dibar2, DIBAR2_value, 4)
#define	KVM_WRITE_DIBAR3_REG_VALUE(DIBAR3_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dibar3, DIBAR3_value, 4)
#define	KVM_WRITE_DIMAR0_REG_VALUE(DIMAR0_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dimar0, DIMAR0_value, 4)
#define	KVM_WRITE_DIMAR1_REG_VALUE(DIMAR1_value)	\
			NATIVE_SET_DSREG_CLOSED_NOEXC(dimar1, DIMAR1_value, 4)

/*
 * Read/write double-word Compilation Unit Types Descriptor (TSD)
 */
#define	KVM_READ_TSD_REG_VALUE()		GUEST_GET_CPU_DSREG(TSD)

#define	KVM_WRITE_TSD_REG_VALUE(TSD_value)	\
		GUEST_SET_CPU_DSREG(TSD, TSD_value)

/*
 * Read/write word Processor State Register (PSR)
 */
#define	KVM_READ_PSR_REG_VALUE()	\
({ \
extern void dump_stack(void); \
	unsigned long PSR_value = GUEST_GET_CPU_SREG(E2K_PSR); \
	unsigned long vcpu_base; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_base); \
	if (((kvm_vcpu_state_t *)(vcpu_base))->irqs_under_upsr && \
			((PSR_value & ~PSR_PM) == 0)) \
		dump_stack(); \
	if (IS_HV_GM()) \
		PSR_value = NATIVE_NV_READ_PSR_REG_VALUE(); \
	PSR_value; \
})
#define	BOOT_KVM_READ_PSR_REG_VALUE()	\
({ \
	unsigned long PSR_value; \
	\
	if (BOOT_IS_HV_GM()) \
		PSR_value = NATIVE_NV_READ_PSR_REG_VALUE(); \
	else \
		PSR_value = GUEST_GET_CPU_SREG(E2K_PSR); \
	PSR_value; \
})

#define	KVM_ATOMIC_WRITE_PSR_REG_VALUE(PSR_value, under_upsr)	\
({ \
	KVM_DO_ATOMIC_WRITE_PSR_REG_VALUE(GUEST_VCPU_STATE_GREG, \
		GUEST_CPU_SREG(E2K_PSR), PSR_value, \
		GUEST_IRQS_UNDER_UPSR(), under_upsr); \
	trace_vcpu_psr_update(PSR_value, under_upsr); \
})

#define	BOOT_KVM_ATOMIC_WRITE_PSR_REG_VALUE(PSR_value, under_upsr)	\
({ \
	KVM_DO_ATOMIC_WRITE_PSR_REG_VALUE(GUEST_VCPU_STATE_GREG, \
		GUEST_CPU_SREG(E2K_PSR), PSR_value, \
		GUEST_IRQS_UNDER_UPSR(), under_upsr); \
})

#define	KVM_WRITE_SW_PSR_REG_VALUE(PSR_value)	\
({ \
	kvm_vcpu_state_t *vcpu_state; \
	bool under_upsr; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	under_upsr = vcpu_state->irqs_under_upsr; \
	if (((PSR_value) & (PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) == \
			(PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) \
		under_upsr = true; \
	if (((PSR_value) & (PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) == 0) \
		under_upsr = false; \
	KVM_ATOMIC_WRITE_PSR_REG_VALUE(PSR_value, under_upsr); \
})

#define	BOOT_KVM_WRITE_SW_PSR_REG_VALUE(PSR_value)	\
({ \
	kvm_vcpu_state_t *vcpu_state; \
	bool under_upsr; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	under_upsr = vcpu_state->irqs_under_upsr; \
	if (((PSR_value) & (PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) == \
			(PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) \
		under_upsr = true; \
	if (((PSR_value) & (PSR_IE | PSR_NMIE | PSR_UIE | PSR_UNMIE)) == 0) \
		under_upsr = false; \
	BOOT_KVM_ATOMIC_WRITE_PSR_REG_VALUE(PSR_value, under_upsr); \
})
#define	KVM_WRITE_PSR_REG_VALUE(PSR_value)	\
({ \
	KVM_WRITE_SW_PSR_REG_VALUE(PSR_value); \
	if (IS_HV_GM()) \
		NATIVE_WRITE_PSR_REG_VALUE(PSR_value); \
})
#define	BOOT_KVM_WRITE_PSR_REG_VALUE(PSR_value)	\
({ \
	BOOT_KVM_WRITE_SW_PSR_REG_VALUE(PSR_value); \
	if (BOOT_IS_HV_GM()) \
		NATIVE_WRITE_PSR_REG_VALUE(PSR_value); \
})

#define	KVM_WRITE_PSR_REG(PSR)	\
		KVM_WRITE_PSR_REG_VALUE((PSR).PSR_reg)

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	KVM_READ_UPSR_REG_VALUE()	\
({ \
	unsigned long UPSR_value; \
	\
	if (IS_HV_GM()) \
		UPSR_value = NATIVE_NV_READ_UPSR_REG_VALUE(); \
	else \
		UPSR_value = GUEST_GET_CPU_SREG(UPSR); \
	UPSR_value; \
})
#define	BOOT_KVM_READ_UPSR_REG_VALUE()	\
({ \
	unsigned long UPSR_value; \
	\
	if (BOOT_IS_HV_GM()) \
		UPSR_value = NATIVE_NV_READ_UPSR_REG_VALUE(); \
	else \
		UPSR_value = GUEST_GET_CPU_SREG(UPSR); \
	UPSR_value; \
})

#define	KVM_ATOMIC_WRITE_UPSR_REG_VALUE(UPSR_value)	\
({ \
	KVM_DO_ATOMIC_WRITE_UPSR_REG_VALUE(GUEST_VCPU_STATE_GREG, \
		GUEST_CPU_SREG(UPSR), UPSR_value); \
})

#define	BOOT_KVM_ATOMIC_WRITE_UPSR_REG_VALUE(UPSR_value)	\
({ \
	KVM_DO_ATOMIC_WRITE_UPSR_REG_VALUE(GUEST_VCPU_STATE_GREG, \
		GUEST_CPU_SREG(UPSR), UPSR_value); \
})

#if	defined(CONFIG_DIRECT_VIRQ_INJECTION)
#define	KVM_WRITE_UPSR_REG_VALUE(UPSR_value)	\
({ \
	kvm_vcpu_state_t *vcpu_state; \
	bool under_upsr; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	under_upsr = vcpu_state->irqs_under_upsr; \
	KVM_ATOMIC_WRITE_UPSR_REG_VALUE(UPSR_value); \
	if (under_upsr && vcpu_state->lapic.virqs_num.counter) { \
		if ((UPSR_value) & UPSR_IE) { \
			trace_vcpu_upsr_update(UPSR_value, true); \
			kvm_hypervisor_inject_interrupt(); \
		} \
	} else { \
		trace_vcpu_upsr_update(UPSR_value, false); \
	} \
})
#define	BOOT_KVM_WRITE_UPSR_REG_VALUE(UPSR_value)	\
({ \
	kvm_vcpu_state_t *vcpu_state; \
	bool under_upsr; \
	\
	KVM_GET_VCPU_STATE_BASE(vcpu_state); \
	under_upsr = vcpu_state->irqs_under_upsr; \
	BOOT_KVM_ATOMIC_WRITE_UPSR_REG_VALUE(UPSR_value); \
	if (under_upsr && vcpu_state->lapic.virqs_num.counter) { \
		if ((UPSR_value) & UPSR_IE) \
			HYPERVISOR_inject_interrupt(); \
	} \
})
#else	/* ! CONFIG_DIRECT_VIRQ_INJECTION */
#define	KVM_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	BOOT_KVM_WRITE_UPSR_REG_VALUE(UPSR_value)
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

#define	KVM_WRITE_UPSR_REG(UPSR)	\
		KVM_WRITE_UPSR_REG_VALUE((UPSR).UPSR_reg)

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	KVM_READ_PFPFR_REG_VALUE()	NATIVE_GET_SREG_OPEN(pfpfr)
#define	KVM_READ_FPCR_REG_VALUE()	NATIVE_GET_SREG_OPEN(fpcr)
#define	KVM_READ_FPSR_REG_VALUE()	NATIVE_GET_SREG_OPEN(fpsr)

#define	KVM_WRITE_PFPFR_REG_VALUE(PFPFR_value)	\
				NATIVE_SET_SREG_OPEN(pfpfr, PFPFR_value)
#define	KVM_WRITE_FPCR_REG_VALUE(FPCR_value)	\
				NATIVE_SET_SREG_OPEN(fpcr, FPCR_value)
#define	KVM_WRITE_FPSR_REG_VALUE(FPSR_value)	\
				NATIVE_SET_SREG_OPEN(fpsr, FPSR_value)

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	KVM_READ_CS_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(CS_lo)
#define	KVM_READ_CS_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(CS_hi)
#define	KVM_READ_DS_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(DS_lo)
#define	KVM_READ_DS_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(DS_hi)
#define	KVM_READ_ES_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(ES_lo)
#define	KVM_READ_ES_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(ES_hi)
#define	KVM_READ_FS_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(FS_lo)
#define	KVM_READ_FS_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(FS_hi)
#define	KVM_READ_GS_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(GS_lo)
#define	KVM_READ_GS_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(GS_hi)
#define	KVM_READ_SS_LO_REG_VALUE()	GUEST_GET_CPU_DSREG(SS_lo)
#define	KVM_READ_SS_HI_REG_VALUE()	GUEST_GET_CPU_DSREG(SS_hi)

#define	KVM_WRITE_CS_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(CS_lo, sd)
#define	KVM_WRITE_CS_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(CS_hi, sd)
#define	KVM_WRITE_DS_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(DS_lo, sd)
#define	KVM_WRITE_DS_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(DS_hi, sd)
#define	KVM_WRITE_ES_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(ES_lo, sd)
#define	KVM_WRITE_ES_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(ES_hi, sd)
#define	KVM_WRITE_FS_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(FS_lo, sd)
#define	KVM_WRITE_FS_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(FS_hi, sd)
#define	KVM_WRITE_GS_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(GS_lo, sd)
#define	KVM_WRITE_GS_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(GS_hi, sd)
#define	KVM_WRITE_SS_LO_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(SS_lo, sd)
#define	KVM_WRITE_SS_HI_REG_VALUE(sd)	GUEST_SET_CPU_DSREG(SS_hi, sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	KVM_READ_IDR_REG_VALUE()	GUEST_GET_CPU_DSREG(IDR)

/*
 * Read/Write Processor Core Mode Register (CORE_MODE)
 */
#define	KVM_READ_CORE_MODE_REG_VALUE()	\
		GUEST_GET_CPU_DSREG(CORE_MODE)
#define	KVM_WRITE_CORE_MODE_REG_VALUE(modes)	\
		GUEST_SET_CPU_DSREG(CORE_MODE, modes)

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is native (pure) guest kernel */

/*
 * Set flags of updated VCPU registers
 */
#define	PUT_UPDATED_CPU_REGS_FLAGS(flags)	\
		KVM_PUT_UPDATED_CPU_REGS_FLAGS(flags)

#define READ_VCPU_ID()	KVM_READ_VCPU_ID()

/*
 * Read/write word Procedure Stack Harware Top Pointer (PSHTP)
 */
#define READ_PSHTP_REG_VALUE()	KVM_READ_PSHTP_REG_VALUE()
#define WRITE_PSHTP_REG_VALUE(PSHTP_value)	\
		KVM_WRITE_PSHTP_REG_VALUE(PSHTP_value)

/*
 * Read/write word Procedure Chain Stack Harware Top Pointer (PCSHTP)
 */
#define READ_PCSHTP_REG_SVALUE()	KVM_READ_PCSHTP_REG_SVALUE()
#define WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)	\
		KVM_WRITE_PCSHTP_REG_SVALUE(PCSHTP_svalue)

/*
 * Read/write low/high double-word OS Compilation Unit Descriptor (OSCUD)
 */

#define	READ_OSCUD_LO_REG_VALUE()	KVM_READ_OSCUD_LO_REG_VALUE()
#define	READ_OSCUD_HI_REG_VALUE()	KVM_READ_OSCUD_HI_REG_VALUE()
#define	BOOT_READ_OSCUD_LO_REG_VALUE()	BOOT_KVM_READ_OSCUD_LO_REG_VALUE()
#define	BOOT_READ_OSCUD_HI_REG_VALUE()	BOOT_KVM_READ_OSCUD_HI_REG_VALUE()

#define	WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)		\
		KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)		\
		KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)
#define	BOOT_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)	\
		BOOT_KVM_WRITE_OSCUD_LO_REG_VALUE(OSCUD_lo_value)
#define	BOOT_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)	\
		BOOT_KVM_WRITE_OSCUD_HI_REG_VALUE(OSCUD_hi_value)

/*
 * Read/write low/hgh double-word OS Globals Register (OSGD)
 */

#define	READ_OSGD_LO_REG_VALUE()	KVM_READ_OSGD_LO_REG_VALUE()
#define	READ_OSGD_HI_REG_VALUE()	KVM_READ_OSGD_HI_REG_VALUE()
#define	BOOT_READ_OSGD_LO_REG_VALUE()	KVM_READ_OSGD_LO_REG_VALUE()
#define	BOOT_READ_OSGD_HI_REG_VALUE()	KVM_READ_OSGD_HI_REG_VALUE()

#define	WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)	\
		KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)	\
		KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)
#define	BOOT_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)	\
		BOOT_KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value)
#define	BOOT_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)	\
		BOOT_KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value)
#define WRITE_OSGD_REG_VALUE(OSGD_hi_value, OSGD_lo_value) \
do { \
	KVM_WRITE_OSGD_LO_REG_VALUE(OSGD_lo_value); \
	KVM_WRITE_OSGD_HI_REG_VALUE(OSGD_hi_value); \
} while (0)

/*
 * Read/write low/high double-word Compilation Unit Register (CUD)
 */

#define	READ_CUD_LO_REG_VALUE()		KVM_READ_CUD_LO_REG_VALUE()
#define	READ_CUD_HI_REG_VALUE()		KVM_READ_CUD_HI_REG_VALUE()
#define	BOOT_READ_CUD_LO_REG_VALUE()	KVM_READ_CUD_LO_REG_VALUE()
#define	BOOT_READ_CUD_HI_REG_VALUE()	KVM_READ_CUD_HI_REG_VALUE()

#define	WRITE_CUD_LO_REG_VALUE(CUD_lo_value)		\
		KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	WRITE_CUD_HI_REG_VALUE(CUD_hi_value)		\
		KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)
#define	BOOT_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)	\
		BOOT_KVM_WRITE_CUD_LO_REG_VALUE(CUD_lo_value)
#define	BOOT_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)	\
		BOOT_KVM_WRITE_CUD_HI_REG_VALUE(CUD_hi_value)

/*
 * Read/write low/high double-word Globals Register (GD)
 */

#define	READ_GD_LO_REG_VALUE()		KVM_READ_GD_LO_REG_VALUE()
#define	READ_GD_HI_REG_VALUE()		KVM_READ_GD_HI_REG_VALUE()
#define	BOOT_READ_GD_LO_REG_VALUE()	KVM_READ_GD_LO_REG_VALUE()
#define	BOOT_READ_GD_HI_REG_VALUE()	KVM_READ_GD_HI_REG_VALUE()

#define	WRITE_GD_LO_REG_VALUE(GD_lo_value)		\
		KVM_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	WRITE_GD_HI_REG_VALUE(GD_hi_value)		\
		KVM_WRITE_GD_HI_REG_VALUE(GD_hi_value)
#define	BOOT_WRITE_GD_LO_REG_VALUE(GD_lo_value)	\
		BOOT_KVM_WRITE_GD_LO_REG_VALUE(GD_lo_value)
#define	BOOT_WRITE_GD_HI_REG_VALUE(GD_hi_value)	\
		BOOT_KVM_WRITE_GD_HI_REG_VALUE(GD_hi_value)

/*
 * Read/write low/high quad-word Procedure Stack Pointer Register (PSP)
 */

#define READ_PSP_LO_REG_VALUE()	KVM_READ_PSP_LO_REG_VALUE()
#define READ_PSP_HI_REG_VALUE()	KVM_READ_PSP_HI_REG_VALUE()
#define BOOT_READ_PSP_LO_REG_VALUE()	KVM_READ_PSP_LO_REG_VALUE()
#define BOOT_READ_PSP_HI_REG_VALUE()	KVM_READ_PSP_HI_REG_VALUE()

#define WRITE_PSP_LO_REG_VALUE(PSP_lo_value)		\
 	      	KVM_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define WRITE_PSP_HI_REG_VALUE(PSP_hi_value)		\
      	 	KVM_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)
#define BOOT_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)	\
      	 	KVM_WRITE_PSP_LO_REG_VALUE(PSP_lo_value)
#define BOOT_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)	\
		KVM_WRITE_PSP_HI_REG_VALUE(PSP_hi_value)

/*
 * Read/write low/high quad-word Procedure Chain Stack Pointer Register (PCSP)
 */
#define READ_PCSP_LO_REG_VALUE()	KVM_READ_PCSP_LO_REG_VALUE()
#define READ_PCSP_HI_REG_VALUE()	KVM_READ_PCSP_HI_REG_VALUE()
#define BOOT_READ_PCSP_LO_REG_VALUE()	KVM_READ_PCSP_LO_REG_VALUE()
#define BOOT_READ_PCSP_HI_REG_VALUE()	KVM_READ_PCSP_HI_REG_VALUE()

#define WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)	 \
		KVM_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)	\
		KVM_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)
#define BOOT_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)	\
		KVM_WRITE_PCSP_LO_REG_VALUE(PCSP_lo_value)
#define BOOT_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)	\
		KVM_WRITE_PCSP_HI_REG_VALUE(PCSP_hi_value)

/*
 * Read/write low/high quad-word Current Chain Register (CR0/CR1)
 */
#define	READ_CR0_LO_REG_VALUE()	KVM_READ_CR0_LO_REG_VALUE()
#define	READ_CR0_HI_REG_VALUE()	KVM_READ_CR0_HI_REG_VALUE()
#define	READ_CR1_LO_REG_VALUE()	KVM_READ_CR1_LO_REG_VALUE()
#define	READ_CR1_HI_REG_VALUE()	KVM_READ_CR1_HI_REG_VALUE()

#define	WRITE_CR0_LO_REG_VALUE(CR0_lo_value) \
		KVM_WRITE_CR0_LO_REG_VALUE(CR0_lo_value)
#define	WRITE_CR0_HI_REG_VALUE(CR0_hi_value) \
		KVM_WRITE_CR0_HI_REG_VALUE(CR0_hi_value)
#define	WRITE_CR1_LO_REG_VALUE(CR1_lo_value) \
		KVM_WRITE_CR1_LO_REG_VALUE(CR1_lo_value)
#define	WRITE_CR1_HI_REG_VALUE(CR1_hi_value) \
		KVM_WRITE_CR1_HI_REG_VALUE(CR1_hi_value)

/*
 * Read/write double-word Control Transfer Preparation Registers
 * (CTPR1/CTPR2/CTPR3)
 */
#define	READ_CTPR_REG_VALUE(reg_no)	KVM_READ_CTPR_REG_VALUE(reg_no)

#define	WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)	\
		KVM_WRITE_CTPR_REG_VALUE(reg_no, CTPR_value)

/*
 * Read/write low/high double-word Trap Info Registers (TIRs)
 */
#define	READ_TIR_LO_REG_VALUE()	KVM_READ_TIR_LO_REG_VALUE()
#define	READ_TIR_HI_REG_VALUE()	KVM_READ_TIR_HI_REG_VALUE()

#define	WRITE_TIR_LO_REG_VALUE(TIR_lo_value) \
		KVM_WRITE_TIR_LO_REG_VALUE(TIR_lo_value)
#define	WRITE_TIR_HI_REG_VALUE(TIR_hi_value) \
		KVM_WRITE_TIR_HI_REG_VALUE(TIR_hi_value)

/*
 * Read/write low/high double-word Non-Protected User Stack Descriptor
 * Register (USD)
 */
#define	READ_USD_LO_REG_VALUE()		KVM_READ_USD_LO_REG_VALUE()
#define	READ_USD_HI_REG_VALUE()		KVM_READ_USD_HI_REG_VALUE()
#define	BOOT_READ_USD_LO_REG_VALUE()	KVM_READ_USD_LO_REG_VALUE()
#define	BOOT_READ_USD_HI_REG_VALUE()	KVM_READ_USD_HI_REG_VALUE()

#define	WRITE_USD_LO_REG_VALUE(USD_lo_value)		\
		KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	WRITE_USD_HI_REG_VALUE(USD_hi_value)		\
		KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value)
#define	BOOT_WRITE_USD_LO_REG_VALUE(USD_lo_value)	\
		KVM_WRITE_USD_LO_REG_VALUE(USD_lo_value)
#define	BOOT_WRITE_USD_HI_REG_VALUE(USD_hi_value)	\
		KVM_WRITE_USD_HI_REG_VALUE(USD_hi_value)

/*
 * Read/write low/high double-word Protected User Stack Descriptor
 * Register (PUSD)
 */
#define	READ_PUSD_LO_REG_VALUE()	KVM_READ_PUSD_LO_REG_VALUE()
#define	READ_PUSD_HI_REG_VALUE()	KVM_READ_PUSD_HI_REG_VALUE()

#define	WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value) \
		KVM_WRITE_PUSD_LO_REG_VALUE(PUSD_lo_value)
#define	WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value) \
		KVM_WRITE_PUSD_HI_REG_VALUE(PUSD_hi_value)

/*
 * Read/write double-word User Stacks Base Register (USBR)
 */
#define	READ_SBR_REG_VALUE()		KVM_READ_SBR_REG_VALUE()
#define	READ_USBR_REG_VALUE()		KVM_READ_USBR_REG_VALUE()
#define	BOOT_READ_USBR_REG_VALUE()	KVM_READ_USBR_REG_VALUE()
#define	BOOT_READ_SBR_REG_VALUE()	KVM_READ_SBR_REG_VALUE()

#define	WRITE_SBR_REG_VALUE(SBR_value)		\
		KVM_WRITE_SBR_REG_VALUE(SBR_value)
#define	WRITE_USBR_REG_VALUE(USBR_value)		\
		KVM_WRITE_USBR_REG_VALUE(USBR_value)
#define	NV_WRITE_USBR_USD_REG_VALUE(usbr, usd_hi, usd_lo)	\
		KVM_NV_WRITE_USBR_USD_REG_VALUE(usbr, usd_hi, usd_lo)
#define	BOOT_WRITE_USBR_REG_VALUE(USBR_value)	\
		KVM_WRITE_USBR_REG_VALUE(USBR_value)
#define	BOOT_WRITE_SBR_REG_VALUE(SBR_value)		\
		KVM_WRITE_SBR_REG_VALUE(SBR_value)
#define	BOOT_NV_WRITE_USBR_USD_REG_VALUE(usbr, usd_hi, usd_lo)	\
		KVM_NV_WRITE_USBR_USD_REG_VALUE(usbr, usd_hi, usd_lo)

/*
 * Read/write double-word Window Descriptor Register (WD)
 */
#define	READ_WD_REG_VALUE()		KVM_READ_WD_REG_VALUE()
#define	WRITE_WD_REG_VALUE(WD_value)	KVM_WRITE_WD_REG_VALUE(WD_value)

/*
 * Read/write double-word Loop Status Register (LSR)
 */
#define	READ_LSR_REG_VALUE()			\
		KVM_READ_LSR_REG_VALUE()
#define	WRITE_LSR_REG_VALUE(LSR_value)	\
		KVM_WRITE_LSR_REG_VALUE(LSR_value)

/*
 * Read/write double-word Initial Loop Counters Register (ILCR)
 */
#define	READ_ILCR_REG_VALUE()		\
		KVM_READ_ILCR_REG_VALUE()
#define	WRITE_ILCR_REG_VALUE(ILCR_value)	\
		KVM_WRITE_ILCR_REG_VALUE(ILCR_value)

/*
 * Read/write OS register which point to current process thread info
 * structure (OSR0)
 */
#define	READ_CURRENT_REG_VALUE()	KVM_READ_CURRENT_REG_VALUE()
#define	BOOT_READ_CURRENT_REG_VALUE()	BOOT_KVM_READ_CURRENT_REG_VALUE()

#define	WRITE_CURRENT_REG_VALUE(osr0_value)		\
		KVM_WRITE_CURRENT_REG_VALUE(osr0_value)
#define	BOOT_WRITE_CURRENT_REG_VALUE(osr0_value)	\
		BOOT_KVM_WRITE_CURRENT_REG_VALUE(osr0_value)

/*
 * Read/write OS Entries Mask (OSEM)
 */
#define	READ_OSEM_REG_VALUE()		\
		KVM_READ_OSEM_REG_VALUE()
#define	WRITE_OSEM_REG_VALUE(OSEM_value)	\
		KVM_WRITE_OSEM_REG_VALUE(OSEM_value)

/*
 * Read/write word Base Global Register (BGR)
 */
#define	READ_BGR_REG_VALUE()		KVM_READ_BGR_REG_VALUE()
#define	BOOT_READ_BGR_REG_VALUE()	KVM_READ_BGR_REG_VALUE()

#define	WRITE_BGR_REG_VALUE(BGR_value)	\
		KVM_WRITE_BGR_REG_VALUE(BGR_value)
#define	BOOT_WRITE_BGR_REG_VALUE(BGR_value)	\
		BOOT_KVM_WRITE_BGR_REG_VALUE(BGR_value)

/*
 * Read CPU current clock regigister (CLKR)
 */
#define	READ_CLKR_REG_VALUE()	KVM_READ_CLKR_REG_VALUE()

/*
 * Read/Write system clock registers (SCLKM)
 */
#define	READ_SCLKR_REG_VALUE()	KVM_READ_SCLKR_REG_VALUE()
#define	READ_SCLKM1_REG_VALUE()	KVM_READ_SCLKM1_REG_VALUE()
#define	READ_SCLKM2_REG_VALUE()	KVM_READ_SCLKM2_REG_VALUE()
#define	READ_SCLKM3_REG_VALUE()	KVM_READ_SCLKM3_REG_VALUE()

#define	WRITE_SCLKR_REG_VALUE(reg_value)	\
		KVM_WRITE_SCLKR_REG_VALUE(reg_value)
#define	WRITE_SCLKM1_REG_VALUE(reg_value)	\
		KVM_WRITE_SCLKM1_REG_VALUE(reg_value)
#define	WRITE_SCLKM2_REG_VALUE(reg_value)	\
		KVM_WRITE_SCLKM2_REG_VALUE(reg_value)
#define	WRITE_SCLKM3_REG_VALUE(reg_value)	\
		KVM_WRITE_SCLKM3_REG_VALUE(reg_value)

/*
 * Read/Write Control Unit HardWare registers (CU_HW0/CU_HW1)
 */
#define	READ_CU_HW0_REG_VALUE()	KVM_READ_CU_HW0_REG_VALUE()
#define	READ_CU_HW1_REG_VALUE()	KVM_READ_CU_HW1_REG_VALUE()

#define	WRITE_CU_HW0_REG_VALUE(reg)	KVM_WRITE_CU_HW0_REG_VALUE(reg)
#define	WRITE_CU_HW1_REG_VALUE(reg)	KVM_WRITE_CU_HW1_REG_VALUE(reg)

/*
 * Read/write low/high double-word Recovery point register (RPR)
 */
#define	READ_RPR_LO_REG_VALUE()	KVM_READ_RPR_LO_REG_VALUE()
#define	READ_RPR_HI_REG_VALUE()	KVM_READ_RPR_HI_REG_VALUE()
#define	READ_SBBP_REG_VALUE()	KVM_READ_SBBP_REG_VALUE()

#define	WRITE_RPR_LO_REG_VALUE(RPR_lo_value) \
		KVM_WRITE_RPR_LO_REG_VALUE(RPR_lo_value)
#define	WRITE_RPR_HI_REG_VALUE(RPR_hi_value) \
		KVM_WRITE_RPR_HI_REG_VALUE(RPR_hi_value)

/*
 * Read double-word CPU current Instruction Pointer register (IP)
 */
#define	READ_IP_REG_VALUE()		KVM_READ_IP_REG_VALUE()

/*
 * Read debug and monitors regigisters
 */
#define	READ_DIBCR_REG_VALUE()	KVM_READ_DIBCR_REG_VALUE()
#define	READ_DIBSR_REG_VALUE()	KVM_READ_DIBSR_REG_VALUE()
#define	READ_DIMCR_REG_VALUE()	KVM_READ_DIMCR_REG_VALUE()
#define	READ_DIBAR0_REG_VALUE()	KVM_READ_DIBAR0_REG_VALUE()
#define	READ_DIBAR1_REG_VALUE()	KVM_READ_DIBAR1_REG_VALUE()
#define	READ_DIBAR2_REG_VALUE()	KVM_READ_DIBAR2_REG_VALUE()
#define	READ_DIBAR3_REG_VALUE()	KVM_READ_DIBAR3_REG_VALUE()
#define	READ_DIMAR0_REG_VALUE()	KVM_READ_DIMAR0_REG_VALUE()
#define	READ_DIMAR1_REG_VALUE()	KVM_READ_DIMAR1_REG_VALUE()

#define	WRITE_DIBCR_REG_VALUE(DIBCR_value)	\
		KVM_WRITE_DIBCR_REG_VALUE(DIBCR_value)
#define	WRITE_DIBSR_REG_VALUE(DIBSR_value)	\
		KVM_WRITE_DIBSR_REG_VALUE(DIBSR_value)
#define	WRITE_DIMCR_REG_VALUE(DIMCR_value)	\
		KVM_WRITE_DIMCR_REG_VALUE(DIMCR_value)
#define	WRITE_DIBAR0_REG_VALUE(DIBAR0_value)	\
		KVM_WRITE_DIBAR0_REG_VALUE(DIBAR0_value)
#define	WRITE_DIBAR1_REG_VALUE(DIBAR1_value)	\
		KVM_WRITE_DIBAR1_REG_VALUE(DIBAR1_value)
#define	WRITE_DIBAR2_REG_VALUE(DIBAR2_value)	\
		KVM_WRITE_DIBAR2_REG_VALUE(DIBAR2_value)
#define	WRITE_DIBAR3_REG_VALUE(DIBAR3_value)	\
		KVM_WRITE_DIBAR3_REG_VALUE(DIBAR3_value)
#define	WRITE_DIMAR0_REG_VALUE(DIMAR0_value)	\
		KVM_WRITE_DIMAR0_REG_VALUE(DIMAR0_value)
#define	WRITE_DIMAR1_REG_VALUE(DIMAR1_value)	\
		KVM_WRITE_DIMAR1_REG_VALUE(DIMAR1_value)

/*
 * Read/write double-word Compilation Unit Table Register (CUTD)
 */
#define	READ_CUTD_REG_VALUE()		\
		KVM_READ_CUTD_REG_VALUE()
#define READ_OSCUTD_REG_VALUE()		KVM_READ_OSCUTD_REG_VALUE()
#define	WRITE_CUTD_REG_VALUE(CUTD_value)	\
		KVM_WRITE_CUTD_REG_VALUE(CUTD_value)
#define WRITE_OSCUTD_REG_VALUE(OSCUTD_value)	\
		KVM_WRITE_OSCUTD_REG_VALUE(OSCUTD_value)
#define BOOT_READ_CUTD_REG_VALUE()	BOOT_KVM_READ_CUTD_REG_VALUE()
#define BOOT_READ_OSCUTD_REG_VALUE()	BOOT_KVM_READ_OSCUTD_REG_VALUE()
#define BOOT_WRITE_CUTD_REG_VALUE(CUTD_value)	\
		BOOT_KVM_WRITE_CUTD_REG_VALUE(CUTD_value)
#define BOOT_WRITE_OSCUTD_REG_VALUE(CUTD_value)	\
		BOOT_KVM_WRITE_OSCUTD_REG_VALUE(CUTD_value)

/*
 * Read word Compilation Unit Index Register (CUIR)
 */
#define	READ_CUIR_REG_VALUE()		KVM_READ_CUIR_REG_VALUE()
#define	WRITE_CUIR_REG_VALUE(v)		KVM_WRITE_CUIR_REG_VALUE(v)
#define	READ_OSCUIR_REG_VALUE()		KVM_READ_OSCUIR_REG_VALUE()
#define	WRITE_OSCUIR_REG_VALUE(v)	KVM_WRITE_OSCUIR_REG_VALUE(v)
#define	BOOT_READ_CUIR_REG_VALUE()	BOOT_KVM_READ_CUIR_REG_VALUE()
#define	BOOT_WRITE_CUIR_REG_VALUE(v)	BOOT_KVM_WRITE_CUIR_REG_VALUE(v)
#define	BOOT_READ_OSCUIR_REG_VALUE()	BOOT_KVM_READ_OSCUIR_REG_VALUE()
#define	BOOT_WRITE_OSCUIR_REG_VALUE(v)	BOOT_KVM_WRITE_OSCUIR_REG_VALUE(v)

/*
 * Read/write double-word Compilation Unit Types Descriptor (TSD)
 */
#define	READ_TSD_REG_VALUE()			\
		KVM_READ_TSD_REG_VALUE()
#define	WRITE_TSD_REG_VALUE(TSD_value)	\
		KVM_WRITE_TSD_REG_VALUE(TSD_value)

/*
 * Read/write double-word Type Descriptor (TD) and current Type Register (TR)
 */
#define	READ_TD_REG_VALUE()		KVM_READ_TD_REG_VALUE()
#define	READ_TR_REG_VALUE()		KVM_READ_TR_REG_VALUE()

#define	WRITE_TD_REG_VALUE(TD_value)	KVM_WRITE_TD_REG_VALUE(TD_value)
#define	WRITE_TR_REG_VALUE(TR_value)	KVM_WRITE_TR_REG_VALUE(TR_value)

/*
 * Read/write word Processor State Register (PSR)
 */
#define	READ_PSR_REG_VALUE()		KVM_READ_PSR_REG_VALUE()
#define	BOOT_READ_PSR_REG_VALUE()	BOOT_KVM_READ_PSR_REG_VALUE()

#define	WRITE_PSR_REG_VALUE(PSR_value)	\
		KVM_WRITE_PSR_REG_VALUE(PSR_value)
#define	BOOT_WRITE_PSR_REG_VALUE(PSR_value)	\
		BOOT_KVM_WRITE_PSR_REG_VALUE(PSR_value)
#define KVM_WRITE_PSR_IRQ_BARRIER(PSR_value) \
		KVM_WRITE_PSR_REG_VALUE(PSR_value)
#define	WRITE_PSR_IRQ_BARRIER(PSR_value)	\
		KVM_WRITE_PSR_IRQ_BARRIER(PSR_value)

/*
 * Read/write word User Processor State Register (UPSR)
 */
#define	READ_UPSR_REG_VALUE()		KVM_READ_UPSR_REG_VALUE()
#define	BOOT_READ_UPSR_REG_VALUE()	BOOT_KVM_READ_UPSR_REG_VALUE()

#define	WRITE_UPSR_REG_VALUE(UPSR_value)		\
		KVM_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	BOOT_WRITE_UPSR_REG_VALUE(UPSR_value)	\
		BOOT_KVM_WRITE_UPSR_REG_VALUE(UPSR_value)
#define	WRITE_UPSR_IRQ_BARRIER(UPSR_value)	\
		KVM_WRITE_UPSR_REG_VALUE(UPSR_value)

/*
 * Read/write word floating point control registers (PFPFR/FPCR/FPSR)
 */
#define	READ_PFPFR_REG_VALUE()	KVM_READ_PFPFR_REG_VALUE()
#define	READ_FPCR_REG_VALUE()	KVM_READ_FPCR_REG_VALUE()
#define	READ_FPSR_REG_VALUE()	KVM_READ_FPSR_REG_VALUE()

#define	WRITE_PFPFR_REG_VALUE(PFPFR_value)	\
		KVM_WRITE_PFPFR_REG_VALUE(PFPFR_value)
#define	WRITE_FPCR_REG_VALUE(FPCR_value)	\
		KVM_WRITE_FPCR_REG_VALUE(FPCR_value)
#define	WRITE_FPSR_REG_VALUE(FPSR_value)	\
		KVM_WRITE_FPSR_REG_VALUE(FPSR_value)

/*
 * Read/write low/high double-word Intel segments registers (xS)
 */

#define	READ_CS_LO_REG_VALUE()	KVM_READ_CS_LO_REG_VALUE()
#define	READ_CS_HI_REG_VALUE()	KVM_READ_CS_HI_REG_VALUE()
#define	READ_DS_LO_REG_VALUE()	KVM_READ_DS_LO_REG_VALUE()
#define	READ_DS_HI_REG_VALUE()	KVM_READ_DS_HI_REG_VALUE()
#define	READ_ES_LO_REG_VALUE()	KVM_READ_ES_LO_REG_VALUE()
#define	READ_ES_HI_REG_VALUE()	KVM_READ_ES_HI_REG_VALUE()
#define	READ_FS_LO_REG_VALUE()	KVM_READ_FS_LO_REG_VALUE()
#define	READ_FS_HI_REG_VALUE()	KVM_READ_FS_HI_REG_VALUE()
#define	READ_GS_LO_REG_VALUE()	KVM_READ_GS_LO_REG_VALUE()
#define	READ_GS_HI_REG_VALUE()	KVM_READ_GS_HI_REG_VALUE()
#define	READ_SS_LO_REG_VALUE()	KVM_READ_SS_LO_REG_VALUE()
#define	READ_SS_HI_REG_VALUE()	KVM_READ_SS_HI_REG_VALUE()

#define	WRITE_CS_LO_REG_VALUE(sd)	KVM_WRITE_CS_LO_REG_VALUE(sd)
#define	WRITE_CS_HI_REG_VALUE(sd)	KVM_WRITE_CS_HI_REG_VALUE(sd)
#define	WRITE_DS_LO_REG_VALUE(sd)	KVM_WRITE_DS_LO_REG_VALUE(sd)
#define	WRITE_DS_HI_REG_VALUE(sd)	KVM_WRITE_DS_HI_REG_VALUE(sd)
#define	WRITE_ES_LO_REG_VALUE(sd)	KVM_WRITE_ES_LO_REG_VALUE(sd)
#define	WRITE_ES_HI_REG_VALUE(sd)	KVM_WRITE_ES_HI_REG_VALUE(sd)
#define	WRITE_FS_LO_REG_VALUE(sd)	KVM_WRITE_FS_LO_REG_VALUE(sd)
#define	WRITE_FS_HI_REG_VALUE(sd)	KVM_WRITE_FS_HI_REG_VALUE(sd)
#define	WRITE_GS_LO_REG_VALUE(sd)	KVM_WRITE_GS_LO_REG_VALUE(sd)
#define	WRITE_GS_HI_REG_VALUE(sd)	KVM_WRITE_GS_HI_REG_VALUE(sd)
#define	WRITE_SS_LO_REG_VALUE(sd)	KVM_WRITE_SS_LO_REG_VALUE(sd)
#define	WRITE_SS_HI_REG_VALUE(sd)	KVM_WRITE_SS_HI_REG_VALUE(sd)

/*
 * Read doubleword User Processor Identification Register (IDR)
 */
#define	READ_IDR_REG_VALUE()		KVM_READ_IDR_REG_VALUE()
#define	BOOT_READ_IDR_REG_VALUE()	KVM_READ_IDR_REG_VALUE()

/*
 * Read/Write Processor Core Mode Register (CORE_MODE) and
 */
#define	READ_CORE_MODE_REG_VALUE()	\
		KVM_READ_CORE_MODE_REG_VALUE()
#define	BOOT_READ_CORE_MODE_REG_VALUE()	\
		KVM_READ_CORE_MODE_REG_VALUE()
#define	WRITE_CORE_MODE_REG_VALUE(modes)	\
		KVM_WRITE_CORE_MODE_REG_VALUE(modes)
#define	BOOT_WRITE_CORE_MODE_REG_VALUE(modes)	\
		KVM_WRITE_CORE_MODE_REG_VALUE(modes)

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* ! __ASSEMBLY__ */

#endif	/* __KERNEL__ */

#endif	/* _E2K_KVM_CPU_REGS_ACCESS_H_ */
