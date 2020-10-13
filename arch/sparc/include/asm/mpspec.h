#ifndef __ASM_MPSPEC_H
#define __ASM_MPSPEC_H

#include <linux/numa.h>
#ifdef CONFIG_E90S
#include <asm/e90s.h>
#endif

#include <asm-l/mpspec.h>

/* all addresses in MP table is virtual so do not change them */
#define	mpc_addr_to_virt(addr)		((void *)(addr))
#define	mpc_addr_to_phys(addr)		(addr)

#endif	/* __ASM_MPSPEC_H */
