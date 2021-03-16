#ifndef	_E2K_KVM_GUEST_VGA_H_
#define	_E2K_KVM_GUEST_VGA_H_

#include <linux/types.h>

/*
 * VGA screen support
 * VGA Video Memory emulated as part of common guest VCPUs virtual memory
 */
#define	KVM_VGA_VRAM_PHYS_BASE	GUEST_VCPU_VRAM_PHYS_BASE
#define	KVM_VGA_VRAM_OFFSET	VGA_VRAM_PHYS_BASE	/* a0000 - c0000 */
#define	KVM_VGA_VRAM_START	KVM_VGA_VRAM_OFFSET
#define	KVM_VGA_VRAM_SIZE	VGA_VRAM_SIZE
#define	KVM_VGA_VRAM_END	(KVM_VGA_VRAM_START + KVM_VGA_VRAM_SIZE)
#define	KVM_VGA_VRAM_VIRT_TO_PHYS(addr)	virt_to_phys(addr)
#define	KVM_VGA_VRAM_PHYS_TO_VIRT(addr)	phys_to_virt(addr)

#define	KVM_IS_PHYS_MEM_MAP_ADDR(addr)	\
		((addr) >= GUEST_PAGE_OFFSET &&	\
			(addr) < (GUEST_PAGE_OFFSET + MAX_PM_SIZE))
#define	KVM_IS_VGA_VRAM_PHYS_ADDR(addr)	\
		((addr) >= KVM_VGA_VRAM_START && (addr) < KVM_VGA_VRAM_END)
#define	KVM_IS_VGA_VRAM_VIRT_ADDR(addr)	\
		KVM_IS_VGA_VRAM_PHYS_ADDR(KVM_VGA_VRAM_VIRT_TO_PHYS(addr))

extern void kvm_scr_writew(u16 val, volatile u16 *addr);
extern u16 kvm_scr_readw(volatile const u16 *addr);
extern void kvm_vga_writeb(u8 val, volatile u8 *addr);
extern u8 kvm_vga_readb(volatile const u8 *addr);

#ifdef	CONFIG_KVM_GUEST_KERNEL
static inline void scr_writew(u16 val, volatile u16 *addr)
{
	kvm_scr_writew(val, addr);
}

static inline u16 scr_readw(volatile const u16 *addr)
{
	return kvm_scr_readw(addr);
}
static inline void vga_writeb(u8 val, volatile u8 *addr)
{
	kvm_vga_writeb(val, addr);
}

static inline u8 vga_readb(volatile const u8 *addr)
{
	return kvm_vga_readb(addr);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif  /* _E2K_KVM_GUEST_VGA_H_ */
