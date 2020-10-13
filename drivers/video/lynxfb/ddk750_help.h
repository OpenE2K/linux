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
#ifndef DDK750_HELP_H__
#define DDK750_HELP_H__
#include "ddk750_chip.h"
#ifndef USE_INTERNAL_REGISTER_ACCESS

#include <linux/ioport.h>
#include <asm/io.h>
#include <asm/uaccess.h>

#ifdef CONFIG_FB_LYNXFB_DOMAINS
#include <asm-l/iolinkmask.h>
#endif

#include "lynx_help.h"

#ifdef CONFIG_FB_LYNXFB_DOMAINS
 /* software control endianess */
#define PEEK32(addr, domain) readl((addr) + mmio750[domain])
#define POKE32(addr, data, domain) writel((data), (addr) + mmio750[domain])
#else
 /* software control endianess */
#define PEEK32(addr) readl((addr) + mmio750)
#define POKE32(addr, data) writel((data), (addr) + mmio750)
#endif /* CONFIG_FB_LYNXFB_DOMAINS */


#ifdef CONFIG_FB_LYNXFB_DOMAINS
extern volatile unsigned char __iomem *mmio750[MAX_NUMIOLINKS];
extern char revId750[MAX_NUMIOLINKS];
extern unsigned short devId750[MAX_NUMIOLINKS];
#else
extern volatile unsigned char __iomem *mmio750;
extern char revId750;
extern unsigned short devId750;
#endif /* CONFIG_FB_LYNXFB_DOMAINS */


#else
/* implement if you want use it*/
#endif

#endif
