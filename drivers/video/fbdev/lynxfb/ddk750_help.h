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
#include <linux/sched.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include "lynx_help.h"


 /* software control endianess */
#define __PEEK32(addr) __raw_readl((addr) + mmio750)
#define __POKE32(addr, data) __raw_writel((data), (addr) + mmio750)

#define PEEK8(addr) __raw_readb((addr) + mmio750)
#define POKE8(addr, data) __raw_writeb((data), (addr) + mmio750)

/*#define DEBUG_REGS*/

#ifdef DEBUG_REGS
#define PEEK32(__offset)				\
({							\
	unsigned __val = __PEEK32(__offset);		\
	printk(KERN_DEBUG"R: %x: %x: %s\t%s:%d\n",	\
		(u32)(__offset), __val, # __offset,	\
			__func__, __LINE__);		\
	__val;						\
})

#define POKE32(__offset, __val)	do {			\
	unsigned __val2 = __val;			\
	printk(KERN_DEBUG"W: %x: %x: %s\t%s:%d\n",	\
		(u32)(__offset), __val2, # __offset,	\
		__func__, __LINE__);			\
	__POKE32(__offset, __val2);			\
} while (0)

#else
#define		PEEK32		__PEEK32
#define		POKE32		__POKE32
#endif

extern volatile unsigned char __iomem *mmio750;
extern char revId750;
extern unsigned short devId750;
#else
/* implement if you want use it*/
#endif

#endif
