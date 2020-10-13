/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
/*#include "ddk750_reg.h" */
/*#include "ddk750_chip.h" */
#include "ddk750_help.h"

#ifdef CONFIG_FB_LYNXFB_DOMAINS
volatile unsigned char __iomem *mmio750[MAX_NUMIOLINKS];
char revId750[MAX_NUMIOLINKS];
unsigned short devId750[MAX_NUMIOLINKS];
#else
volatile unsigned char __iomem *mmio750;
char revId750;
unsigned short devId750;
#endif /* CONFIG_FB_LYNXFB_DOMAINS */

/* after driver mapped io registers, use this function first */
#ifdef CONFIG_FB_LYNXFB_DOMAINS
void ddk750_set_mmio(volatile unsigned char *addr, unsigned short devId,
		     unsigned char revId, int domain)
{
	mmio750[domain] = addr;
	devId750[domain] = devId;
	revId750[domain] = revId;
	if (revId == 0xfe)
		printk("found sm750le on domain %d\n", domain);
}
#else
void ddk750_set_mmio(volatile unsigned char *addr, unsigned short devId,
		     unsigned char revId)
{
	mmio750 = addr;
	devId750 = devId;
	revId750 = revId;
	if (revId == 0xfe)
		printk("found sm750le\n");
}
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
