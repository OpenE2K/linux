#ifndef _DDK768_HELP_H__
#define _DDK768_HELP_H__

#ifndef USE_INTERNAL_REGISTER_ACCESS

#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <drm/drmP.h>

#define __PEEK32(addr) readl((addr)+mmio768)
#define __POKE32(addr,data) writel((data),(addr)+mmio768)

#define DEBUG_REGS

#ifdef DEBUG_REGS
#if 0
#define PEEK32(__offset)				\
({							\
	unsigned __val = __PEEK32(__offset);		\
	DRM_DEBUG("R: %x: %x: %s\t%s:%d: %pf\n",	\
		(u32)(__offset), __val, # __offset,	\
			__func__, __LINE__, __builtin_return_address(0));		\
	__val;						\
})
#else
#define		PEEK32		__PEEK32
#endif

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

#define peekRegisterByte(addr) readb((addr)+mmio768)
#define pokeRegisterByte(addr,data) writeb((data),(addr)+mmio768)

/* Size of SM768 MMIO and memory */
#define SM768_PCI_ALLOC_MMIO_SIZE       (2*1024*1024)
#define SM768_PCI_ALLOC_MEMORY_SIZE     (128*1024*1024)

void ddk768_set_mmio(volatile unsigned char * addr,unsigned short devId,char revId);

extern volatile unsigned  char __iomem * mmio768;
extern char revId768;
extern unsigned short devId768;
#else
/* implement if you want use it*/
#endif

#endif
