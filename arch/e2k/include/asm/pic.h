#ifndef __ASM_E2K_PIC_H
#define __ASM_E2K_PIC_H

/*
 * Choose between APIC and EPIC basic functions
 */

#include <asm/apic.h>
#include <asm/epic.h>
#include <asm/machdep.h>

/* P2V */
static inline unsigned int boot_epic_is_bsp(void)
{
	union cepic_ctrl reg;

	reg.raw = boot_epic_read_w(CEPIC_CTRL);
	return reg.bits.bsp_core;
}

static inline unsigned int boot_apic_is_bsp(void)
{
	return BootStrap(boot_arch_apic_read(APIC_BSP));
}

static inline unsigned int boot_epic_read_id(void)
{
	return cepic_id_full_to_short(boot_epic_read_w(CEPIC_ID));
}

static inline unsigned int boot_apic_read_id(void)
{
	return GET_APIC_ID(boot_arch_apic_read(APIC_ID));
}

/*
 * Reading PIC registers is mainly done in early P2V: before and slightly
 * after the initialization of boot_machine structure. Unfortunately, the
 * structure is initalized by BSP, and AP may proceed to read PIC in the mean
 * time. The barrier can't be used that early either. As such, PIC reads in P2V
 * can't rely on CPU_FEAT_EPIC. We manually read the IDR register instead.
 */
#ifdef	CONFIG_EPIC
static inline bool boot_early_pic_is_bsp(void)
{
	e2k_idr_t idr;
	unsigned int reg;

	idr = boot_read_IDR_reg();
	if (idr.IDR_mdl >= IDR_E12C_MDL)
		reg = boot_epic_is_bsp();
	else
		reg = boot_apic_is_bsp();

	return !!reg;
}

static inline unsigned int boot_early_pic_read_id(void)
{
	e2k_idr_t idr;

	idr = boot_read_IDR_reg();
	if (idr.IDR_mdl >= IDR_E12C_MDL)
		return boot_epic_read_id();
	else
		return boot_apic_read_id();
}
#else
static inline bool boot_early_pic_is_bsp(void)
{
	return !!boot_apic_is_bsp();
}

static inline unsigned int boot_early_pic_read_id(void)
{
	return boot_apic_read_id();
}
#endif

/* Kernel */
#ifndef	E2K_P2V
#include <asm-l/pic.h>

#ifdef	CONFIG_EPIC
static inline bool read_pic_bsp(void)
{
	if (cpu_has_epic())
		return read_epic_bsp();
	else
		return !!BootStrap(arch_apic_read(APIC_BSP));
}

extern void __init_recv e2k_setup_secondary_apic(void);
static inline void __init_recv e2k_setup_secondary_pic(void)
{
	if (cpu_has_epic())
		setup_cepic();
	else
		e2k_setup_secondary_apic();
}

extern void __init_recv setup_prepic(void);
static inline void __init_recv setup_processor_pic(void)
{
	if (cpu_has_epic())
		setup_prepic();
}
#else	/* CONFIG_EPIC */
static inline bool read_pic_bsp(void)
{
	return !!BootStrap(arch_apic_read(APIC_BSP));
}

extern void __init_recv e2k_setup_secondary_apic(void);
static inline void __init_recv e2k_setup_secondary_pic(void)
{
	e2k_setup_secondary_apic();
}

extern void __init_recv e2k_apic_map_logical_id(int recovery);
static inline void __init_recv e2k_pic_map_logical_id(int recovery)
{
	e2k_apic_map_logical_id(recovery);
}

static inline void __init_recv setup_processor_pic(void)
{
	/* Nothing to do */
}

extern void setup_secondary_APIC_clock(void);
static inline void __init_recv setup_secondary_pic_clock(void)
{
	setup_secondary_APIC_clock();
}

static inline int pic_get_vector(void)
{
	return apic_get_vector();
}

struct pci_dev;
int ioepic_pin_to_msi_ioapic_irq(unsigned int pin, struct pci_dev *dev);
static inline int ioepic_pin_to_irq_pic(unsigned int pin, struct pci_dev *dev)
{
	return ioepic_pin_to_msi_ioapic_irq(pin, dev);
}
#endif	/* CONFIG_EPIC */
#endif	/* E2K_P2V */
#endif	/* __ASM_E2K_PIC_H */
