/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPARC_MMAN_H__
#define __SPARC_MMAN_H__

#include <uapi/asm/mman.h>

#ifndef __ASSEMBLY__
#define arch_mmap_check(addr,len,flags)	sparc_mmap_check(addr,len)
int sparc_mmap_check(unsigned long addr, unsigned long len);

#ifdef CONFIG_SPARC64
static inline unsigned long arch_calc_vm_prot_bits(unsigned long prot,
						   unsigned long pkey)
{
	return (prot & PROT_INVEND) ? VM_INVEND : 0;
}
#define arch_calc_vm_prot_bits arch_calc_vm_prot_bits

static inline pgprot_t arch_vm_get_page_prot(unsigned long vm_flags)
{
	return (vm_flags & VM_INVEND) ? __pgprot(_PAGE_IE) : __pgprot(0);
}
#define arch_vm_get_page_prot	arch_vm_get_page_prot

static inline int arch_validate_prot(unsigned long prot, unsigned long addr)
{
	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM |
			PROT_INVEND))
		return 0;
	return 1;
}
#define arch_validate_prot	arch_validate_prot

#endif	/*CONFIG_SPARC64*/
#endif	/*__ASSEMBLY__*/
#endif /* __SPARC_MMAN_H__ */
