#include <linux/kernel.h>
#include <asm/e2k.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_console.h>

#undef  BOOT_DEBUG_SIC_MODE
#undef  BootDebugSIC
#define	BOOT_DEBUG_SIC_MODE	0	/* SIC mapping & init */
#define	BootDebugSIC(fmt, args...)					\
		({ if (BOOT_DEBUG_SIC_MODE)				\
			dump_printk(fmt, ##args); })

#ifndef CONFIG_E2K_MACHINE
int boot_get_e2k_machine_id(void)
{
	e2k_idr_t idr;
	int mdl;
	int mach_id;

	idr = boot_read_IDR_reg();
	mdl = idr.IDR_mdl;
	BootDebugSIC("boot_get_e2k_machine_id() CPU model is %d, IDR 0x%llx\n",
		mdl, idr.IDR_reg);
#if CONFIG_E2K_MINVER == 2
	if (mdl == IDR_ES2_DSP_MDL) {
		mach_id = MACHINE_ID_ES2_DSP;
	} else if (mdl == IDR_ES2_RU_MDL) {
		mach_id = MACHINE_ID_ES2_RU;
	} else
#endif
#if CONFIG_E2K_MINVER <= 3
	if (mdl == IDR_E2S_MDL) {
		mach_id = MACHINE_ID_E2S;
	} else
#endif
#if CONFIG_E2K_MINVER <= 4
	if (mdl == IDR_E8C_MDL) {
		mach_id = MACHINE_ID_E8C;
	} else if (mdl == IDR_E1CP_MDL) {
		mach_id = MACHINE_ID_E1CP;
	} else
#endif
#if CONFIG_E2K_MINVER <= 5
	if (mdl == IDR_E8C2_MDL) {
		mach_id = MACHINE_ID_E8C2;
	} else
#endif
#if CONFIG_E2K_MINVER <= 6
	if (mdl == IDR_E12C_MDL) {
		mach_id = MACHINE_ID_E12C;
	} else if (mdl == IDR_E16C_MDL) {
		mach_id = MACHINE_ID_E16C;
	} else if (mdl == IDR_E2C3_MDL) {
		mach_id = MACHINE_ID_E2C3;
	} else
#endif
	{
		BootDebugSIC("Undefined CPU model number %d\n", mdl);
		return MACHINE_ID_NONE;
	}

	return mach_id;
}
#endif

void boot_e2k_sic_setup_arch(void)
{
	if (BOOT_HAS_MACHINE_E2K_FULL_SIC) {
		boot_machine.x86_io_area_base = E2K_FULL_SIC_IO_AREA_PHYS_BASE;
		boot_machine.x86_io_area_size = E2K_FULL_SIC_IO_AREA_SIZE;
	} else if (BOOT_HAS_MACHINE_E2K_LEGACY_SIC) {
		boot_machine.x86_io_area_base =
			E2K_LEGACY_SIC_IO_AREA_PHYS_BASE;
		boot_machine.x86_io_area_size = E2K_LEGACY_SIC_IO_AREA_SIZE;
	} else {
		do_boot_printk("boot_e2k_sic_setup_arch(): this machine does not have SIC\n");
	}
	boot_machine.native_rev = boot_read_IDR_reg().IDR_rev;
}

