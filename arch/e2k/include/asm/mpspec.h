#ifndef __ASM_MPSPEC_H
#define __ASM_MPSPEC_H

#ifdef __KERNEL__

#include <linux/numa.h>
#include <asm/e2k.h>

#include <asm/byteorder.h> /* For __LITTLE_ENDIAN definition */

/* all addresses in MP table is physical so do not change them */
#define	mpc_addr_to_virt(addr)		phys_to_virt(boot_vpa_to_pa(addr))
#define	mpc_addr_to_phys(addr)		(addr)
#define	mpc_addr(addr)						\
	((READ_OSCUD_LO_REG().OSCUD_lo_base >= PAGE_OFFSET) ?	\
			(u64)mpc_addr_to_virt(addr) : mpc_addr_to_phys(addr))

static inline int
boot_mpf_do_checksum(unsigned char *mp, int len)
{
	int sum = 0;

	while (len--)
		sum += *mp++;

	return 0x100 - (sum & 0xFF);
}

#endif  /* __KERNEL__ */

#if defined(__KERNEL__) || defined(__KVM_MPSPEC_SUPPORT__)
#include <asm-l/mpspec.h>
#endif  /* __KERNEL__ || __KVM_MPSPEC_SUPPORT__ */

#endif	/* __ASM_MPSPEC_H */
