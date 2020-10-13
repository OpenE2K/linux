/*
 * Small boot for simulator
 */

#include <linux/types.h>
#include <asm/bootinfo.h>

#ifndef _E2k_BOOT_BOOT_H_
#define _E2k_BOOT_BOOT_H_

extern void *malloc_aligned(int size, int alignment);
extern void *malloc(int size);
extern void bios_mem_init(long membase, long memsize);
extern e2k_addr_t get_busy_memory_end(void);

extern int  decompress_kernel(void *dst, void *src, ulong size);
extern void rom_stdio_init(void);
extern void rom_putc(char c);
extern int  rom_getc(void);
extern int  rom_tstc(void);

#ifdef	CONFIG_SMP
extern void smp_start_cpus(void);
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_STATE_SAVE
extern void load_machine_state_new(boot_info_t *boot_info);
#endif	/* CONFIG_STATE_SAVE */

#endif	/* _E2k_BOOT_BOOT_H_ */
