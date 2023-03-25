
#ifndef _ASM_E2K_KVM_HEAD_H
#define	_ASM_E2K_KVM_HEAD_H

#include <linux/types.h>

/*
 * Kernel virtual memory layout
 */
#ifdef	CONFIG_VIRTUALIZATION
/*
 * it can be:
 *	paravirtualized host and guest kernel
 *	native host kernel with virtualization support
 *	pure guest kernel (not paravirtualized based on pv_ops)
 */

/* 0x0000 e200 0000 0000 - 0x0000 e200 3fff ffff host image area + modules */
#define	HOST_KERNEL_IMAGE_AREA_BASE	NATIVE_KERNEL_IMAGE_AREA_BASE
/* 0x0000 2e00 0000 0000 - 0x0000 2e00 3fff ffff shadow host image area + */
/*						 modules at guest space */
#define	SHADOW_KERNEL_IMAGE_AREA_BASE	0x00002e0000000000
#endif	/* CONFIG_VIRTUALIZATION */

#if	!defined(CONFIG_VIRTUALIZATION)
/* it is native kernel without any virtualization */
#include <asm/pv_info.h>

#define	E2K_KERNEL_IMAGE_AREA_BASE	NATIVE_KERNEL_IMAGE_AREA_BASE
#elif	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native host kernel with virtualization support */

#define	E2K_KERNEL_IMAGE_AREA_BASE	HOST_KERNEL_IMAGE_AREA_BASE
#define	GUEST_KERNEL_IMAGE_AREA_BASE	SHADOW_KERNEL_IMAGE_AREA_BASE
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/pv_info.h>

#define	E2K_KERNEL_IMAGE_AREA_BASE	GUEST_KERNEL_IMAGE_AREA_BASE
#define	GUEST_KERNEL_IMAGE_AREA_BASE	SHADOW_KERNEL_IMAGE_AREA_BASE
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/pv_info.h>

#define	E2K_KERNEL_IMAGE_AREA_BASE	HOST_KERNEL_IMAGE_AREA_BASE
#define	GUEST_KERNEL_IMAGE_AREA_BASE	NATIVE_KERNEL_IMAGE_AREA_BASE
#else
 #error	"Unknown virtualization type"
#endif	/* ! CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_VIRTUALIZATION

#ifndef	__ASSEMBLY__
#include <asm/kvm/guest.h>
#endif	/* !__ASSEMBLY__ */

#define	HOST_KERNEL_PHYS_MEM_VIRT_BASE	HOST_PAGE_OFFSET  /* 0x0000c000 ... */
#define	GUEST_KERNEL_PHYS_MEM_VIRT_BASE	GUEST_PAGE_OFFSET /* 0x00002000 ... */
#define	GUEST_IO_PORTS_VIRT_BASE	0x00003f7e7e000000UL

#define GUEST_NBSR_BASE			THE_NODE_NBSR_PHYS_BASE(0);

/*
 * Guest physical memory (RAM) is emulated as one or more host virtual
 * contigous areas (gfn + GUEST_PAGE_OFFSET)
 *
 * Probably it should be different for different architecture release
 * 0x0000 0000 0000 0000 - 0x0000 00ef ffff ffff now limited like this,
 * 0x0000 2000 0000 0000 - 0x0000 20ff ffff ffff but limit can be decremented
 */

#define	GUEST_RAM_PHYS_BASE		0x0000000000000000UL
#define	GUEST_MAX_RAM_SIZE		0x000000f000000000UL
#define GUEST_RAM_VIRT_BASE		\
		(GUEST_RAM_PHYS_BASE + GUEST_PAGE_OFFSET)

/*
 * Virtual memory (VRAM) is used to emulate VCPUs (CPU, MMU, SIC, VIRQ VCPU,
 * other hardware) registers, tables, structures.
 * Now it should be of size to locate VCPU state and CUT of guest kernel
 *
 * WARNING: VRAM physical base should not intersects with real physical
 * memory address space layout. Probably it should be different for different
 * architecture
 * 0x0000 00ff 0000 0000 - 0x0000 00ff 00ff ffff should not be valid for
 * 0x0000 20ff 0000 0000 - 0x0000 20ff 00ff ffff real memory layout
 */

/* Macros defines VRAM for one VCPU or VIRQ VCPU, */
/* but VRAM should be created for all VCPU and VIRQ VCPU */
#define	GUEST_ONE_VCPU_VRAM_SIZE	sizeof(kvm_vcpu_state_t)
#define	HOST_INFO_VCPU_VRAM_SIZE	sizeof(kvm_host_info_t)
#define	GUEST_VCPU_VRAM_PHYS_BASE	0x000000ff00000000UL
#define	GUEST_MAX_VCPU_VRAM_SIZE	0x0000000001000000UL
#define GUEST_VCPU_VRAM_VIRT_BASE	\
		(GUEST_VCPU_VRAM_PHYS_BASE + GUEST_PAGE_OFFSET)

/*
 * Virtual IO memory (IO-VRAM) is used to emulate ISA, VGA low memory ...
 * Now this memory is used only to emulate VGA low memory
 *
 * WARNING: IO-VRAM physical base should not intersects with real physical
 * memory address space layout and VRAM.
 * Probably it should be different for different architecture release
 * 0x0000 00ff 0100 0000 - 0x0000 00ff 010f ffff should not be valid for
 * 0x0000 20ff 0100 0000 - 0x0000 20ff 010f ffff real memory layout and VRAM
 */

#define	GUEST_IO_VRAM_PHYS_BASE		0x000000ff01000000UL
#define	GUEST_IO_VRAM_SIZE		0x0000000000100000UL
#define GUEST_IO_VRAM_VIRT_BASE		\
		(GUEST_IO_VRAM_PHYS_BASE + GUEST_PAGE_OFFSET)

#endif	/* CONFIG_VIRTUALIZATION */

#endif /* ! _ASM_E2K_KVM_HEAD_H */
