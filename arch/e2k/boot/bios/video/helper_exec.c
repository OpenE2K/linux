/* $XFree86: xc/programs/Xserver/hw/xfree86/int10/helper_exec.c,v 1.16 2001/04/30 14:34:57 tsi Exp $ */
/*
 *                   XFree86 int10 module
 *   execute BIOS int 10h calls in x86 real mode environment
 *                 Copyright 1999 Egbert Eich
 *
 *   Part of this is based on code taken from DOSEMU
 *   (C) Copyright 1992, ..., 1999 the "DOSEMU-Development-Team"
 */

/*
 * To debug port accesses define PRINT_PORT.
 * Note! You also have to comment out ioperm()
 * in xf86EnableIO(). Otherwise we won't trap
 * on PIO.
 */
#include <x86emu.h>
#include "init.h"
#include "console/printk.h"
#include "pci.h"

/* general software interrupt handler */
u32 getIntVect(int num)
{
	return MEM_RW(num << 2) + (MEM_RW((num << 2) + 2) << 4);
}

void pushw(u16 val)
{
	X86_ESP -= 2;
	MEM_WW(((u32) X86_SS << 4) + X86_SP, val);
}

int run_bios_int(int num)
{
	u32 eflags;

	eflags = X86_EFLAGS;
	pushw(eflags);
	pushw(X86_CS);
	pushw(X86_IP);
	X86_CS = MEM_RW((num << 2) + 2);
	X86_IP = MEM_RW(num << 2);

//	printf("%s: INT %x CS:IP = %x:%x\n", __FUNCTION__,
//	       num, MEM_RW((num << 2) + 2), MEM_RW(num << 2));

	return 1;
}