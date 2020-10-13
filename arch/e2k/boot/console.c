
#include <linux/types.h>
#include <stdarg.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>
#include "boot_io.h"

#if defined(CONFIG_BIOS)
#include "bios/bios.h"
#endif

static inline unsigned int e2k_rom_debug_inl(__u16 port)
{
	return E2K_READ_MAS_W(PHYS_X86_IO_BASE + port, MAS_IOADDR);
}

static inline void e2k_rom_debug_outb(__u16 port, __u8 byte)
{
       E2K_WRITE_MAS_B(PHYS_X86_IO_BASE + port, byte, MAS_IOADDR);
}

static inline void e2k_rom_debug_putc(char c)
{
	while (e2k_rom_debug_inl(LMS_CONS_DATA_PORT));

	e2k_rom_debug_outb(LMS_CONS_DATA_PORT, c);
	e2k_rom_debug_outb(LMS_CONS_DATA_PORT, 0);
}


void console_probe(void)
{
#if defined(CONFIG_BIOS)
	if (e2k_rom_debug_inl(LMS_CONS_DATA_PORT) != 0xFFFFFFFF) {
		hardware.dbgport = 1;
	};
#endif
}


void console_putc(char c)
{
	e2k_rom_debug_putc(c);
}

