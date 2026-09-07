
#ifndef IN_MODULE
#include <stdio.h>
#endif

#include "console/printk.h"

int int16_handler(void)
{
	rom_printk("\nint16: keyboard not supported right now.\n");
	return 1;
}
