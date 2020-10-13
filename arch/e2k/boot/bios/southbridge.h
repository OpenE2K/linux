/* PIIX4 southbridge configuration registers */

#ifndef _SOUTHBRIDGE_H_
#define _SOUTHBRIDGE_H_

///#include <linux/spinlock.h>
#include <asm/head.h>
#include <asm/mas.h>
#include <asm/e2k_api.h>
#include "../boot_io.h"

#define	E3M_SB_VENDOR	PCI_VENDOR_ID_INTEL
#define	E3M_SB_DEVICE	PCI_DEVICE_ID_INTEL_82371AB_0

#if 0
#define	PCI_BUS			0
#define	PHYS_DEV		7
#else
#define	PCI_BUS			SB_bus
#define	PHYS_DEV		SB_device
#endif


/* Nothbridge addr i/o ports 0xcf8 - 0xcfb */
#define		SB_IO_ADDR_BASE		0x0CF8
#define		SB_IO_ADDR_PORT0	0x0CF8
#define		SB_IO_ADDR_PORT1	0x0CF9
#define		SB_IO_ADDR_PORT2	0x0CFA
#define		SB_IO_ADDR_PORT3	0x0CFB

/* Nothbridge data i/o ports 0xcfc - 0xcff */
#define		SB_IO_DATA_BASE		0x0CFC
#define		SB_IO_DATA_PORT0	0x0CFC
#define		SB_IO_DATA_PORT1	0x0CFD
#define		SB_IO_DATA_PORT2	0x0CFE
#define		SB_IO_DATA_PORT3	0x0CFF
	
#define pci_cfg_xaddr(bus,physdev,fun,byte) \
			((byte&~3)|(fun<<8)|(physdev<<11)|(bus<<16)|(1<<31))
	
#define data_port PHYS_X86_IO_BASE + SB_IO_DATA_BASE
#define addr_port PHYS_X86_IO_BASE + SB_IO_ADDR_BASE


#endif /* _SOUTHBRIDGE_H_ */
