#ifndef DDK750_HELP_H__
#define DDK750_HELP_H__
#include <drm/drmP.h>
#include "ddk750_chip.h"
#ifndef USE_INTERNAL_REGISTER_ACCESS

#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include "ddk750_mode.h"

#define __PEEK32(addr) readl((addr)+mmio750)
#define __POKE32(addr,data) writel((data),(addr)+mmio750)

/*#define DEBUG_REGS*/

#ifdef DEBUG_REGS
#define PEEK32(__offset)				\
({							\
	unsigned __val = __PEEK32(__offset);		\
	DRM_DEBUG("R: %x: %x: %s\t%s:%d: %pf\n",	\
		(u32)(__offset), __val, # __offset,	\
			__func__, __LINE__, __builtin_return_address(0));		\
	__val;						\
})

#define POKE32(__offset, __val)	do {			\
	unsigned __val2 = __val;			\
	DRM_DEBUG("W: %x: %x: %s\t%s:%d: %pf\n",	\
		(u32)(__offset), __val2, # __offset,	\
		__func__, __LINE__, __builtin_return_address(0));			\
	__POKE32(__offset, __val2);			\
} while (0)

#else
#define		PEEK32		__PEEK32
#define		POKE32		__POKE32
#endif

#define peekRegisterDWord PEEK32
#define pokeRegisterDWord POKE32

#define __peekRegisterDWord __PEEK32
#define __pokeRegisterDWord __POKE32

#define peekRegisterByte(addr) readb((addr)+mmio750)
#define pokeRegisterByte(addr,data) writeb((data),(addr)+mmio750)

extern volatile unsigned  char __iomem * mmio750;
extern char revId750;
extern unsigned short devId750;
void ddk750_set_mmio(volatile unsigned char *,unsigned short,char);

#else
/* implement if you want use it*/
#endif

#endif

