
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/machdep.h>

static inline unsigned long
read_shadow_cpu_dsreg(const char *name)
{
	pr_err("Shadow register %s is not implemented on the CPU ISET "
		"or compilator is not LCC-1.23\n",
		name);
	return 0;
}
static inline void
write_shadow_cpu_dsreg(const char *name, unsigned long value)
{
	pr_err("Shadow register %s is not implemented on the CPU ISET "
		"or compilator is not LCC-1.23\n",
		name);
}

#if	CONFIG_CPU_ISET >= 6

unsigned long read_VIRT_CTRL_CU_reg_value(void)
{
	return READ_VIRT_CTRL_CU_REG_VALUE();
}
void write_VIRT_CTRL_CU_reg_value(unsigned long value)
{
	WRITE_VIRT_CTRL_CU_REG_VALUE(value);
}

unsigned int read_SH_CORE_MODE_reg_value(void)
{
	return READ_SH_CORE_MODE_REG_VALUE();
}
void write_SH_CORE_MODE_reg_value(unsigned int value)
{
	WRITE_SH_CORE_MODE_REG_VALUE(value);
}
unsigned long read_SH_PSP_LO_reg_value(void)
{
	return READ_SH_PSP_LO_REG_VALUE();
}
unsigned long read_SH_PSP_HI_reg_value(void)
{
	return READ_SH_PSP_HI_REG_VALUE();
}
void write_SH_PSP_LO_reg_value(unsigned long value)
{
	WRITE_SH_PSP_LO_REG_VALUE(value);
}
void write_SH_PSP_HI_reg_value(unsigned long value)
{
	WRITE_SH_PSP_HI_REG_VALUE(value);
}
unsigned long read_BU_PSP_LO_reg_value(void)
{
	return READ_BU_PSP_LO_REG_VALUE();
}
unsigned long read_BU_PSP_HI_reg_value(void)
{
	return READ_BU_PSP_HI_REG_VALUE();
}
void write_BU_PSP_LO_reg_value(unsigned long value)
{
	WRITE_BU_PSP_LO_REG_VALUE(value);
}
void write_BU_PSP_HI_reg_value(unsigned long value)
{
	WRITE_BU_PSP_HI_REG_VALUE(value);
}
unsigned long read_SH_PSHTP_reg_value(void)
{
	return READ_SH_PSHTP_REG_VALUE();
}
void write_SH_PSHTP_reg_value(unsigned long value)
{
	WRITE_SH_PSHTP_REG_VALUE(value);
}
unsigned long read_SH_PCSP_LO_reg_value(void)
{
	return READ_SH_PCSP_LO_REG_VALUE();
}
unsigned long read_SH_PCSP_HI_reg_value(void)
{
	return READ_SH_PCSP_HI_REG_VALUE();
}
void write_SH_PCSP_LO_reg_value(unsigned long value)
{
	WRITE_SH_PCSP_LO_REG_VALUE(value);
}
void write_SH_PCSP_HI_reg_value(unsigned long value)
{
	WRITE_SH_PCSP_HI_REG_VALUE(value);
}
unsigned long read_BU_PCSP_LO_reg_value(void)
{
	return READ_BU_PCSP_LO_REG_VALUE();
}
unsigned long read_BU_PCSP_HI_reg_value(void)
{
	return READ_BU_PCSP_HI_REG_VALUE();
}
void write_BU_PCSP_LO_reg_value(unsigned long value)
{
	WRITE_BU_PCSP_LO_REG_VALUE(value);
}
void write_BU_PCSP_HI_reg_value(unsigned long value)
{
	WRITE_BU_PCSP_HI_REG_VALUE(value);
}
int read_SH_PCSHTP_reg_value(void)
{
	return READ_SH_PCSHTP_REG_SVALUE();
}
void write_SH_PCSHTP_reg_value(int value)
{
	WRITE_SH_PCSHTP_REG_SVALUE(value);
}
unsigned long read_SH_WD_reg_value(void)
{
	return READ_SH_WD_REG_VALUE();
}
void write_SH_WD_reg_value(unsigned long value)
{
	WRITE_SH_WD_REG_VALUE(value);
}

unsigned long read_SH_OSCUD_LO_reg_value(void)
{
	return READ_SH_OSCUD_LO_REG_VALUE();
}
unsigned long read_SH_OSCUD_HI_reg_value(void)
{
	return READ_SH_OSCUD_HI_REG_VALUE();
}
void write_SH_OSCUD_LO_reg_value(unsigned long value)
{
	WRITE_SH_OSCUD_LO_REG_VALUE(value);
}
void write_SH_OSCUD_HI_reg_value(unsigned long value)
{
	WRITE_SH_OSCUD_HI_REG_VALUE(value);
}

unsigned long read_SH_OSGD_LO_reg_value(void)
{
	return READ_SH_OSGD_LO_REG_VALUE();
}
unsigned long read_SH_OSGD_HI_reg_value(void)
{
	return READ_SH_OSGD_HI_REG_VALUE();
}
void write_SH_OSGD_LO_reg_value(unsigned long value)
{
	WRITE_SH_OSGD_LO_REG_VALUE(value);
}
void write_SH_OSGD_HI_reg_value(unsigned long value)
{
	WRITE_SH_OSGD_HI_REG_VALUE(value);
}

unsigned long read_SH_OSCUTD_reg_value(void)
{
	return READ_SH_OSCUTD_REG_VALUE();
}
void write_SH_OSCUTD_reg_value(unsigned long value)
{
	WRITE_SH_OSCUTD_REG_VALUE(value);
}

unsigned int read_SH_OSCUIR_reg_value(void)
{
	return READ_SH_OSCUIR_REG_VALUE();
}
void write_SH_OSCUIR_reg_value(unsigned int value)
{
	WRITE_SH_OSCUIR_REG_VALUE(value);
}

unsigned long read_SH_OSR0_reg_value(void)
{
	return READ_SH_OSR0_REG_VALUE();
}
void write_SH_OSR0_reg_value(unsigned long value)
{
	WRITE_SH_OSR0_REG_VALUE(value);
}

unsigned long read_VIRT_CTRL_MU_reg_value(void)
{
	return READ_VIRT_CTRL_MU_REG_VALUE();
}
void write_VIRT_CTRL_MU_reg_value(unsigned long value)
{
	WRITE_VIRT_CTRL_MU_REG_VALUE(value);
}

unsigned long read_GID_reg_value(void)
{
	return READ_GID_REG_VALUE();
}
void write_GID_reg_value(unsigned long value)
{
	WRITE_GID_REG_VALUE(value);
}

unsigned long read_GP_VPTB_reg_value(void)
{
	return READ_GP_VPTB_REG_VALUE();
}
void write_GP_VPTB_reg_value(unsigned long value)
{
	WRITE_GP_VPTB_REG_VALUE(value);
}

unsigned long read_GP_PPTB_reg_value(void)
{
	return READ_GP_PPTB_REG_VALUE();
}
void write_GP_PPTB_reg_value(unsigned long value)
{
	WRITE_GP_PPTB_REG_VALUE(value);
}

unsigned long read_SH_OS_PPTB_reg_value(void)
{
	return READ_SH_OS_PPTB_REG_VALUE();
}
void write_SH_OS_PPTB_reg_value(unsigned long value)
{
	WRITE_SH_OS_PPTB_REG_VALUE(value);
}

unsigned long read_SH_OS_VPTB_reg_value(void)
{
	return READ_SH_OS_VPTB_REG_VALUE();
}
void write_SH_OS_VPTB_reg_value(unsigned long value)
{
	WRITE_SH_OS_VPTB_REG_VALUE(value);
}

unsigned long read_SH_OS_VAB_reg_value(void)
{
	return READ_SH_OS_VAB_REG_VALUE();
}
void write_SH_OS_VAB_reg_value(unsigned long value)
{
	WRITE_SH_OS_VAB_REG_VALUE(value);
}

unsigned long read_G_W_IMASK_MMU_CR_reg_value(void)
{
	return READ_G_W_IMASK_MMU_CR_REG_VALUE();
}
void write_G_W_IMASK_MMU_CR_reg_value(unsigned long value)
{
	WRITE_G_W_IMASK_MMU_CR_REG_VALUE(value);
}

unsigned long read_SH_PID_reg_value(void)
{
	return READ_SH_PID_REG_VALUE();
}
void write_SH_PID_reg_value(unsigned long value)
{
	WRITE_SH_PID_REG_VALUE(value);
}

unsigned long read_SH_MMU_CR_reg_value(void)
{
	return READ_SH_MMU_CR_REG_VALUE();
}
void write_SH_MMU_CR_reg_value(unsigned long value)
{
	WRITE_SH_MMU_CR_REG_VALUE(value);
}

#elif	CONFIG_CPU_ISET >= 1

unsigned long read_VIRT_CTRL_CU_reg_value(void)
{
	return read_shadow_cpu_dsreg("VIRT_CTRL_CU");
}
void write_VIRT_CTRL_CU_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("VIRT_CTRL_CU", value);
}

unsigned int read_SH_CORE_MODE_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_CORE_MODE");
}
void write_SH_CORE_MODE_reg_value(unsigned int value)
{
	write_shadow_cpu_dsreg("SH_CORE_MODE", value);
}
unsigned long read_SH_PSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSP_LO");
}
unsigned long read_SH_PSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSP_HI");
}
void write_SH_PSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSP_LO", value);
}
void write_SH_PSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSP_HI", value);
}
unsigned long read_BU_PSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PSP_LO");
}
unsigned long read_BU_PSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PSP_HI");
}
void write_BU_PSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PSP_LO", value);
}
void write_BU_PSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PSP_HI", value);
}
unsigned long read_SH_PSHTP_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSHTP");
}
void write_SH_PSHTP_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSHTP", value);
}
unsigned long read_SH_PCSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSP_LO");
}
unsigned long read_SH_PCSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSP_HI");
}
void write_SH_PCSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PCSP_LO", value);
}
void write_SH_PCSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PCSP_HI", value);
}
unsigned long read_BU_PCSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PCSP_LO");
}
unsigned long read_BU_PCSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PCSP_HI");
}
void write_BU_PCSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PCSP_LO", value);
}
void write_BU_PCSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PCSP_HI", value);
}
int read_SH_PCSHTP_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSHTP");
}
void write_SH_PCSHTP_reg_value(int value)
{
	write_shadow_cpu_dsreg("SH_PCSHTP", value);
}
unsigned long read_SH_WD_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_WD");
}
void write_SH_WD_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_WD", value);
}
unsigned long read_SH_OSCUD_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUD_LO");
}
unsigned long read_SH_OSCUD_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUD_HI");
}
void write_SH_OSCUD_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUD_LO", value);
}
void write_SH_OSCUD_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUD_HI", value);
}
unsigned long read_SH_OSGD_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSGD_LO");
}
unsigned long read_SH_OSGD_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSGD_HI");
}
void write_SH_OSGD_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSGD_LO", value);
}
void write_SH_OSGD_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSGD_HI", value);
}
unsigned long read_SH_OSCUTD_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUTD");
}
void write_SH_OSCUTD_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUTD", value);
}
unsigned long read_SH_OSR0_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSR0");
}
void write_SH_OSR0_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSR0", value);
}
unsigned int read_SH_OSCUIR_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUIR");
}
void write_SH_OSCUIR_reg_value(unsigned int value)
{
	write_shadow_cpu_dsreg("SH_OSCUIR", value);
}

unsigned long read_VIRT_CTRL_MU_reg_value(void)
{
	return read_shadow_cpu_dsreg("VIRT_CTRL_MU");
}
void write_VIRT_CTRL_MU_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("VIRT_CTRL_MU", value);
}

unsigned long read_GID_reg_value(void)
{
	return read_shadow_cpu_dsreg("GID");
}
void write_GID_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GID", value);
}

unsigned long read_GP_VPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("GP_VPTB");
}
void write_GP_VPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GP_VPTB", value);
}

unsigned long read_GP_PPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("GP_PPTB");
}
void write_GP_PPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GP_PPTB", value);
}

unsigned long read_SH_OS_PPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_PPTB");
}
void write_SH_OS_PPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_PPTB", value);
}

unsigned long read_SH_OS_VPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_VPTB");
}
void write_SH_OS_VPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_VPTB", value);
}

unsigned long read_SH_OS_VAB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_VAB");
}
void write_SH_OS_VAB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_VAB", value);
}

unsigned long read_G_W_IMASK_MMU_CR_reg_value(void)
{
	return read_shadow_cpu_dsreg("G_W_IMASK_MMU_CR");
}
void write_G_W_IMASK_MMU_CR_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("G_W_IMASK_MMU_CR", value);
}

unsigned long read_SH_PID_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PID");
}
void write_SH_PID_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PID", value);
}

unsigned long read_SH_MMU_CR_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_MMU_CR");
}
void write_SH_MMU_CR_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_MMU_CR", value);
}

#else	/* CONFIG_CPU_ISET is 0 or undefined or negative */
# if	CONFIG_CPU_ISET != 0
# warning "Undefined CPU ISET VERSION #"
# endif

# if __LCC__ >= 123

unsigned long read_VIRT_CTRL_CU_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_VIRT_CTRL_CU_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("VIRT_CTRL_CU");
	}
}
void write_VIRT_CTRL_CU_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_VIRT_CTRL_CU_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("VIRT_CTRL_CU", value);
	}
}

unsigned int read_SH_CORE_MODE_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_CORE_MODE_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_CORE_MODE");
	}
}
void write_SH_CORE_MODE_reg_value(unsigned int value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_CORE_MODE_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_CORE_MODE", value);
	}
}
unsigned long read_SH_PSP_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PSP_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PSP_LO");
	}
}
unsigned long read_SH_PSP_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PSP_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PSP_HI");
	}
}
void write_SH_PSP_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PSP_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PSP_LO", value);
	}
}
void write_SH_PSP_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PSP_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PSP_HI", value);
	}
}
unsigned long read_BU_PSP_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_BU_PSP_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("BU_PSP_LO");
	}
}
unsigned long read_BU_PSP_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_BU_PSP_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("BU_PSP_HI");
	}
}
void write_BU_PSP_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_BU_PSP_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("BU_PSP_LO", value);
	}
}
void write_BU_PSP_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_BU_PSP_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("BU_PSP_HI", value);
	}
}
unsigned long read_SH_PSHTP_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PSHTP_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PSHTP");
	}
}
void write_SH_PSHTP_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PSHTP_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PSHTP", value);
	}
}
unsigned long read_SH_PCSP_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PCSP_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PCSP_LO");
	}
}
unsigned long read_SH_PCSP_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PCSP_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PCSP_HI");
	}
}
void write_SH_PCSP_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PCSP_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PCSP_LO", value);
	}
}
void write_SH_PCSP_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PCSP_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PCSP_HI", value);
	}
}
unsigned long read_BU_PCSP_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_BU_PCSP_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("BU_PCSP_LO");
	}
}
unsigned long read_BU_PCSP_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_BU_PCSP_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("BU_PCSP_HI");
	}
}
void write_BU_PCSP_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_BU_PCSP_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("BU_PCSP_LO", value);
	}
}
void write_BU_PCSP_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_BU_PCSP_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("BU_PCSP_HI", value);
	}
}
int read_SH_PCSHTP_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PCSHTP_REG_SVALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PCSHTP");
	}
}
void write_SH_PCSHTP_reg_value(int value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PCSHTP_REG_SVALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PCSHTP", value);
	}
}
unsigned long read_SH_WD_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_WD_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_WD");
	}
}
void write_SH_WD_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_WD_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_WD", value);
	}
}
unsigned long read_SH_OSCUD_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSCUD_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSCUD_LO");
	}
}
unsigned long read_SH_OSCUD_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSCUD_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSCUD_HI");
	}
}
void write_SH_OSCUD_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSCUD_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSCUD_LO", value);
	}
}
void write_SH_OSCUD_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSCUD_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSCUD_HI", value);
	}
}
unsigned long read_SH_OSGD_LO_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSGD_LO_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSGD_LO");
	}
}
unsigned long read_SH_OSGD_HI_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSGD_HI_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSGD_HI");
	}
}
void write_SH_OSGD_LO_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSGD_LO_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSGD_LO", value);
	}
}
void write_SH_OSGD_HI_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSGD_HI_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSGD_HI", value);
	}
}
unsigned long read_SH_OSCUTD_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSCUTD_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSCUTD");
	}
}
void write_SH_OSCUTD_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSCUTD_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSCUTD", value);
	}
}
unsigned long read_SH_OSR0_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSR0_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSR0");
	}
}
void write_SH_OSR0_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSR0_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSR0", value);
	}
}
unsigned int read_SH_OSCUIR_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OSCUIR_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OSCUIR");
	}
}
void write_SH_OSCUIR_reg_value(unsigned int value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OSCUIR_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OSCUIR", value);
	}
}

unsigned long read_VIRT_CTRL_MU_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_VIRT_CTRL_MU_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("VIRT_CTRL_MU");
	}
}
void write_VIRT_CTRL_MU_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_VIRT_CTRL_MU_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("VIRT_CTRL_MU", value);
	}
}

unsigned long read_GID_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_GID_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("GID");
	}
}
void write_GID_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_GID_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("GID", value);
	}
}

unsigned long read_GP_VPTB_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_GP_VPTB_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("GP_VPTB");
	}
}
void write_GP_VPTB_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_GP_VPTB_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("GP_VPTB", value);
	}
}

unsigned long read_GP_PPTB_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_GP_PPTB_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("GP_PPTB");
	}
}
void write_GP_PPTB_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_GP_PPTB_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("GP_PPTB", value);
	}
}

unsigned long read_SH_OS_PPTB_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OS_PPTB_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OS_PPTB");
	}
}
void write_SH_OS_PPTB_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OS_PPTB_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OS_PPTB", value);
	}
}

unsigned long read_SH_OS_VPTB_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OS_VPTB_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OS_VPTB");
	}
}
void write_SH_OS_VPTB_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OS_VPTB_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OS_VPTB", value);
	}
}

unsigned long read_SH_OS_VAB_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_OS_VAB_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_OS_VAB");
	}
}
void write_SH_OS_VAB_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_OS_VAB_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_OS_VAB", value);
	}
}

unsigned long read_G_W_IMASK_MMU_CR_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_G_W_IMASK_MMU_CR_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("G_W_IMASK_MMU_CR");
	}
}
void write_G_W_IMASK_MMU_CR_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_G_W_IMASK_MMU_CR_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("G_W_IMASK_MMU_CR", value);
	}
}

unsigned long read_SH_PID_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_PID_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_PID");
	}
}
void write_SH_PID_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_PID_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_PID", value);
	}
}

unsigned long read_SH_MMU_CR_reg_value(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		return READ_SH_MMU_CR_REG_VALUE();
	} else {
		return read_shadow_cpu_dsreg("SH_MMU_CR");
	}
}
void write_SH_MMU_CR_reg_value(unsigned long value)
{
	if (machine.native_iset_ver >= E2K_ISET_V6) {
		WRITE_SH_MMU_CR_REG_VALUE(value);
	} else {
		write_shadow_cpu_dsreg("SH_MMU_CR", value);
	}
}
# else	/* __LCC__ < 123 */

unsigned long read_VIRT_CTRL_CU_reg_value(void)
{
	return read_shadow_cpu_dsreg("VIRT_CTRL_CU");
}
void write_VIRT_CTRL_CU_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("VIRT_CTRL_CU", value);
}

unsigned int read_SH_CORE_MODE_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_CORE_MODE");
}
void write_SH_CORE_MODE_reg_value(unsigned int value)
{
	write_shadow_cpu_dsreg("SH_CORE_MODE", value);
}
unsigned long read_SH_PSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSP_LO");
}
unsigned long read_SH_PSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSP_HI");
}
void write_SH_PSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSP_LO", value);
}
void write_SH_PSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSP_HI", value);
}
unsigned long read_BU_PSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PSP_LO");
}
unsigned long read_BU_PSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PSP_HI");
}
void write_BU_PSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PSP_LO", value);
}
void write_BU_PSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PSP_HI", value);
}
unsigned long read_SH_PSHTP_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PSHTP");
}
void write_SH_PSHTP_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PSHTP", value);
}
unsigned long read_SH_PCSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSP_LO");
}
unsigned long read_SH_PCSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSP_HI");
}
void write_SH_PCSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PCSP_LO", value);
}
void write_SH_PCSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PCSP_HI", value);
}
unsigned long read_BU_PCSP_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PCSP_LO");
}
unsigned long read_BU_PCSP_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("BU_PCSP_HI");
}
void write_BU_PCSP_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PCSP_LO", value);
}
void write_BU_PCSP_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("BU_PCSP_HI", value);
}
int read_SH_PCSHTP_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PCSHTP");
}
void write_SH_PCSHTP_reg_value(int value)
{
	write_shadow_cpu_dsreg("SH_PCSHTP", value);
}
unsigned long read_SH_WD_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_WD");
}
void write_SH_WD_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_WD", value);
}
unsigned long read_SH_OSCUD_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUD_LO");
}
unsigned long read_SH_OSCUD_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUD_HI");
}
void write_SH_OSCUD_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUD_LO", value);
}
void write_SH_OSCUD_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUD_HI", value);
}
unsigned long read_SH_OSGD_LO_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSGD_LO");
}
unsigned long read_SH_OSGD_HI_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSGD_HI");
}
void write_SH_OSGD_LO_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSGD_LO", value);
}
void write_SH_OSGD_HI_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSGD_HI", value);
}
unsigned long read_SH_OSCUTD_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUTD");
}
void write_SH_OSCUTD_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSCUTD", value);
}
unsigned long read_SH_OSR0_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSR0");
}
void write_SH_OSR0_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OSR0", value);
}
unsigned int read_SH_OSCUIR_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OSCUIR");
}
void write_SH_OSCUIR_reg_value(unsigned int value)
{
	write_shadow_cpu_dsreg("SH_OSCUIR", value);
}

unsigned long read_VIRT_CTRL_MU_reg_value(void)
{
	return read_shadow_cpu_dsreg("VIRT_CTRL_MU");
}
void write_VIRT_CTRL_MU_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("VIRT_CTRL_MU", value);
}

unsigned long read_GID_reg_value(void)
{
	return read_shadow_cpu_dsreg("GID");
}
void write_GID_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GID", value);
}

unsigned long read_GP_VPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("GP_VPTB");
}
void write_GP_VPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GP_VPTB", value);
}

unsigned long read_GP_PPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("GP_PPTB");
}
void write_GP_PPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("GP_PPTB", value);
}

unsigned long read_SH_OS_PPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_PPTB");
}
void write_SH_OS_PPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_PPTB", value);
}

unsigned long read_SH_OS_VPTB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_VPTB");
}
void write_SH_OS_VPTB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_VPTB", value);
}

unsigned long read_SH_OS_VAB_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_OS_VAB");
}
void write_SH_OS_VAB_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_OS_VAB", value);
}

unsigned long read_G_W_IMASK_MMU_CR_reg_value(void)
{
	return read_shadow_cpu_dsreg("G_W_IMASK_MMU_CR");
}
void write_G_W_IMASK_MMU_CR_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("G_W_IMASK_MMU_CR", value);
}

unsigned long read_SH_PID_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_PID");
}
void write_SH_PID_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_PID", value);
}

unsigned long read_SH_MMU_CR_reg_value(void)
{
	return read_shadow_cpu_dsreg("SH_MMU_CR");
}
void write_SH_MMU_CR_reg_value(unsigned long value)
{
	write_shadow_cpu_dsreg("SH_MMU_CR", value);
}
#endif	/* __LCC >= 123 */

#endif	/* CONFIG_CPU_ISET 0-6 */
