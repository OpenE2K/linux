/*
 *
 * Heading of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_P2V_BOOT_V2P_H
#define	_E2K_P2V_BOOT_V2P_H

#include <linux/types.h>
#include <asm/sections.h>

#include <asm/pv_info.h>
#include <asm/cpu_regs_types.h>
#include <asm/native_cpu_regs_access.h>

#define	EOS_RAM_BASE_LABEL	_data
#define	KERNEL_START_LABEL	_start		/* start label of Linux Image */
#define	KERNEL_END_LABEL	_end		/* end label of Linux Image */

#ifdef __ASSEMBLY__

#define	KERNEL_BASE	[KERNEL_START_LABEL]	/* virtual address of Linux */
						/* Image begining */
#define	KERNEL_END	[KERNEL_END_LABEL]	/* virtual address of Linux */
						/* Image end */
#define	EOS_RAM_BASE	[EOS_RAM_BASE_LABEL]

#else /* !(__ASSEMBLY__) */

#define	EOS_RAM_BASE	((e2k_addr_t)&EOS_RAM_BASE_LABEL)

#define	KERNEL_BASE	((e2k_addr_t)&KERNEL_START_LABEL)
#define	KERNEL_END	((e2k_addr_t)&KERNEL_END_LABEL)

#define	HIGH_PHYS_MEM_SHIFT	32	/* above 2**32 */
#define	HIGH_PHYS_MEM_BASE	(1UL << HIGH_PHYS_MEM_SHIFT)
#define	LOW_PHYS_MEM_MASK	((1UL << HIGH_PHYS_MEM_SHIFT) - 1)

static inline bool
is_addr_from_low_memory(e2k_addr_t addr)
{
	return (addr < HIGH_PHYS_MEM_BASE) ? true : false;
}

static inline bool
is_addr_from_high_memory(e2k_addr_t addr)
{
	return (addr >= HIGH_PHYS_MEM_BASE) ? true : false;
}

/*
 * Convert virtual address of pointer of global or static variable, array,
 * structure, string or other item of linux image to the consistent physical
 * address of one, while booting process is in the progress and virtual memory
 * support is not yet ready.
 * Linker loads Linux image to a virtual space and all enumerated above items
 * have virtual addresses into the image. BIOS loader loads image to the
 * some existing area of physical memory, virtual addressing is off and direct
 * access to the items is impossible.
 * Loader should write pointer of image text segment location in the physical
 * memory to the 'OSCUD' register:
 *			OSCUD.OSCUD_base
 *			OSCUD.OSCUD_size
 * and pointer of image data & bss segments location in the physical memory
 * to the 'OSGD' register:
 *			OSGD.OSGD_base
 *			OSGD.OSGD_size
 * These areas can intersect.
 * If some item of the image (see above) is located into the text, data or
 * bss segment, then to access it on absolute address (pointer) you should
 * call this function to convert absolute virtual address to real physical
 * address.
 *
 * Example:
 *
 *	char	boot_buf[81];
 *	int	boot_buf_size = 80;
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		char	*buf = (char *)boot_va_to_pa((void *)boot_buf);
 *		int	buf_size = *((int *)boot_va_to_pa(
 *						(e2k_addr_t)&boot_buf_size));
 *	.......
 *	}
 *
 * NOTE !!!!! It is rather to use the macroses defined below to access image
 * objects instead of this function. The mocroses have more convenient
 * interfaces
 */

static	inline	void *
boot_native_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	unsigned long os_base;

	os_base = NATIVE_READ_OSCUD_LO_REG_VALUE() & OSCUD_lo_base_mask;
	if (os_base >= NATIVE_KERNEL_VIRTUAL_SPACE_BASE) {
		return virt_pnt;
	} else if ((e2k_addr_t)virt_pnt >= KERNEL_BASE) {
		if (kernel_base == -1)
			kernel_base = os_base;
		return (void *)(kernel_base +
					((e2k_addr_t)virt_pnt - KERNEL_BASE));
	} else {
		return virt_pnt;
	}
}

static	inline	void *
boot_native_va_to_pa(void *virt_pnt)
{
	return boot_native_kernel_va_to_pa(virt_pnt, -1);
}

static	inline	void *
boot_native_func_to_pa(void *virt_pnt)
{
	return boot_native_va_to_pa(virt_pnt);
}

/*
 * In some case kernel boot-time physical address can be appropriate virtual
 * one. For example KVM guest kernel booting on physical memory mapped
 * to virtual space with PAGE_OFFSET
 * So it needs convert a virtual physical address to real physical.
 * Native kernel booting on real physical memory, so convertion does not need
 */
static	inline	e2k_addr_t
boot_native_vpa_to_pa(e2k_addr_t vpa)
{
	return vpa;
}
static	inline	e2k_addr_t
boot_native_pa_to_vpa(e2k_addr_t pa)
{
	return pa;
}
static	inline	e2k_addr_t
native_vpa_to_pa(e2k_addr_t vpa)
{
	return vpa;
}
static	inline	e2k_addr_t
native_pa_to_vpa(e2k_addr_t pa)
{
	return pa;
}

/*
 * Convert pointer of global or static variable, array, structure, string or
 * other item of linux image, which is located into the virtual linux text,
 * data or bss segment to the consistent pointer with physical address of
 * object, while booting process is in the progress and virtual memory
 * support is not yet ready.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	char	boot_buf[81];
 *
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		char	*buf = boot_vp_to_pp(boot_buf);
 *
 *	.......
 *	}
 */

#define	boot_native_vp_to_pp(virt_pnt)		\
		((typeof(virt_pnt))boot_native_va_to_pa((void *)(virt_pnt)))
#define	boot_native_func_to_pp(virt_pnt)		\
		((typeof(virt_pnt))boot_native_va_to_pa((void *)(virt_pnt)))
#define	boot_vp_to_pp(virt_pnt)		\
		((typeof(virt_pnt))boot_va_to_pa((void *)(virt_pnt)))
#define	boot_func_to_pp(virt_pnt)		\
		((typeof(virt_pnt))boot_func_to_pa((void *)(virt_pnt)))

/*
 * Get value of object (variable, array, structure, string or other item of
 * linux image) which is located into the virtual linux text, data or bss
 * segment, while booting process is in the progress and virtual memory support
 * is not yet ready.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	static	long	*boot_long_p;
 *		int	boot_buf_size = 80;
 *
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		int	buf_size = boot_get_vo_value(boot_buf_size);
 *		long	*long_p = boot_get_vo_value(boot_long_p);
 *
 *		long_p[0] = buf_size;
 *	.......
 *	}
 */

#define	boot_native_get_vo_value(virt_value_name) \
		(*(boot_native_vp_to_pp(&virt_value_name)))
#define	boot_get_vo_value(virt_value_name) \
		(*(boot_vp_to_pp(&virt_value_name)))

/*
 * Get name of object (variable, array, structure, string or other item of
 * linux image) which is located into the virtual linux text, data or bss
 * segment, while booting process is in the progress and virtual memory support
 * is not yet ready. This name can be used to assign a value to the object.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	static	int	boot_memory_size;
 *
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		int	total_memory_size = 0;
 *
 *	.......
 *		boot_get_vo_name(boot_memory_size) = total_memory_size;
 *	.......
 *	}
 */

#define	boot_native_get_vo_name(virt_value_name)	\
		(*(typeof(virt_value_name) *)boot_native_vp_to_pp( \
							&virt_value_name))
#define	boot_get_vo_name(virt_value_name)	\
		(*(typeof(virt_value_name) *)boot_vp_to_pp( \
							&virt_value_name))

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/v2p.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops */
#include <asm/kvm/guest/v2p.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */

static	inline	void *
boot_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	return boot_native_kernel_va_to_pa(virt_pnt, kernel_base);
}

static	inline	void *
boot_func_to_pa(void *virt_pnt)
{
	return boot_native_va_to_pa(virt_pnt);
}

static	inline	void *
boot_va_to_pa(void *virt_pnt)
{
	return boot_native_va_to_pa(virt_pnt);
}

static	inline	e2k_addr_t
boot_vpa_to_pa(e2k_addr_t vpa)
{
	return boot_native_vpa_to_pa(vpa);
}

static	inline	e2k_addr_t
boot_pa_to_vpa(e2k_addr_t pa)
{
	return boot_native_pa_to_vpa(pa);
}

static	inline	e2k_addr_t
vpa_to_pa(e2k_addr_t vpa)
{
	return native_vpa_to_pa(vpa);
}

static	inline	e2k_addr_t
pa_to_vpa(e2k_addr_t pa)
{
	return native_pa_to_vpa(pa);
}
#endif	/* CONFIG_PARAVIRT_GUEST */
#endif /* __ASSEMBLY__ */

#endif /* !(_E2K_P2V_BOOT_V2P_H) */
