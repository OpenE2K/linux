#ifndef __L_ASM_SPMC_H__
#define __L_ASM_SPMC_H__

#ifdef CONFIG_ACPI_L_SPMC
extern void do_spmc_halt(void);
#else
static inline void do_spmc_halt(void) {
	printk(KERN_ERR "Board does not use KPI-2: SPMC is not present.\n");
	return;
}
#endif

#endif /* __L_ASM_SPMC_H__ */

