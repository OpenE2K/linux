#ifndef __ASM_MPSPEC_H
#define __ASM_MPSPEC_H

#ifdef __KERNEL__

#include <linux/numa.h>
#include <asm/e2k.h>

#include <asm/byteorder.h> /* For __LITTLE_ENDIAN definition */
#include <asm-l/mpspec.h>

/* all addresses in MP table is physical so do not change them */
#define	mpc_addr_to_virt(addr)		phys_to_virt(addr)
#define	mpc_addr_to_phys(addr)		(addr)

#endif  /* __KERNEL__ */
#endif	/* __ASM_MPSPEC_H */
