/*
 *
 * Heading of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_KVM_GUEST_V2P_H
#define	_E2K_KVM_GUEST_V2P_H

#include <linux/types.h>

#include <asm/cpu_regs_access.h>
#include <asm/page.h>

#ifndef __ASSEMBLY__


#define	kvm_pa(gvpa)		__pa(gvpa)
#define	kvm_va(gpa)		__va(gpa)

static	inline	void *
boot_kvm_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	unsigned long os_base;

	if ((e2k_addr_t)virt_pnt < KERNEL_BASE ||
			(e2k_addr_t)virt_pnt >= KERNEL_END)
		return virt_pnt;
	os_base = BOOT_KVM_READ_OSCUD_LO_REG_VALUE() & OSCUD_lo_base_mask;
	if (os_base >= KERNEL_BASE)
		return virt_pnt;
	if (kernel_base == -1)
		kernel_base = os_base;
	return (void *)(kernel_base + ((e2k_addr_t)virt_pnt - KERNEL_BASE));
}

/*
 * Guest kernel runs into virtual space, so functions can not be converted
 * to virtual physical space (execute protection does not set) and
 * should remain source virtual addresses
 */
static	inline	void *
boot_kvm_func_to_pa(void *virt_pnt)
{
	return boot_kvm_kernel_va_to_pa(virt_pnt, -1);
}

static	inline	void *
boot_kvm_va_to_pa(void *virt_pnt)
{
	return boot_kvm_kernel_va_to_pa(virt_pnt, -1);
}

/*
 * KVM guest kernel booting on physical memory mapped
 * to virtual space with GUEST_PAGE_OFFSET
 * So it needs convert a virtual physical address to real physical.
 */
static	inline	e2k_addr_t
boot_kvm_vpa_to_pa(e2k_addr_t vpa)
{
	return (vpa >= GUEST_PAGE_OFFSET) ? kvm_pa((void *)vpa) : vpa;
}
static	inline	e2k_addr_t
boot_kvm_pa_to_vpa(e2k_addr_t pa)
{
	unsigned long os_base;

	os_base = BOOT_KVM_READ_OSCUD_LO_REG_VALUE() & OSCUD_lo_base_mask;
	if (os_base >= GUEST_PAGE_OFFSET)
		/* VPA is supported */
		return (e2k_addr_t)kvm_va((void *)pa);
	else
		/* nonpaging mode: all addresses can be only physical */
		return pa;
}
static	inline	e2k_addr_t
kvm_vpa_to_pa(e2k_addr_t vpa)
{
	return (vpa >= GUEST_PAGE_OFFSET) ? kvm_pa((void *)vpa) : vpa;
}
static	inline	e2k_addr_t
kvm_pa_to_vpa(e2k_addr_t pa)
{
	return (e2k_addr_t)kvm_va((void *)pa);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops */
static	inline	void *
boot_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	return boot_kvm_kernel_va_to_pa(virt_pnt, kernel_base);
}
static	inline	void *
boot_func_to_pa(void *virt_pnt)
{
	return boot_kvm_func_to_pa(virt_pnt);
}

static	inline	void *
boot_va_to_pa(void *virt_pnt)
{
	return boot_kvm_va_to_pa(virt_pnt);
}

static	inline	e2k_addr_t
boot_vpa_to_pa(e2k_addr_t vpa)
{
	return boot_kvm_vpa_to_pa(vpa);
}
static	inline	e2k_addr_t
boot_pa_to_vpa(e2k_addr_t pa)
{
	return boot_kvm_pa_to_vpa(pa);
}

static	inline	e2k_addr_t
vpa_to_pa(e2k_addr_t vpa)
{
	return kvm_vpa_to_pa(vpa);
}
static	inline	e2k_addr_t
pa_to_vpa(e2k_addr_t pa)
{
	return kvm_pa_to_vpa(pa);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* __ASSEMBLY__ */

#endif /* !(_E2K_KVM_GUEST_V2P_H) */
