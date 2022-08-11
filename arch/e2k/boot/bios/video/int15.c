
#ifndef IN_MODULE
#include <stdio.h>
#endif

#include "init.h"
#include "printk.h"

void x86emu_dump_xregs(void);

int int15_handler(void)
{
#ifdef DEBUG
	rom_printk("\nint15 encountered.\n");
	x86emu_dump_xregs();
#endif
	X86_EAX = 0;
	return 1;
}
