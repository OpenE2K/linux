/* PIIX4 southbridge configuration registers */

#ifndef _SOUTHBRIDGE_H_
#define _SOUTHBRIDGE_H_

#include <asm/head.h>
#include <asm/mas.h>
#include <asm/e2k_api.h>
#include "../boot_io.h"

extern int SB_bus, SB_device, SB_function;

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

#define data_port PHYS_IO_BASE + SB_IO_DATA_BASE
#define addr_port PHYS_IO_BASE + SB_IO_ADDR_BASE

static inline unsigned int SB_read_config(int reg, int func, int size)
{
	unsigned int xaddr;
	int mask = reg & 0x3;
	int rval = 0;
	int cnt = 0;
	xaddr = pci_cfg_xaddr(PCI_BUS, PHYS_DEV, func, reg);
	NATIVE_WRITE_MAS_W(addr_port, xaddr, MAS_IOADDR);
	while (mask) {
		rval |= (NATIVE_READ_MAS_B(data_port + mask,
						MAS_IOADDR) << (cnt * 8));
		if (!--size)
			break;
		++mask;
		++cnt;
		if (mask == 4) {
			xaddr = pci_cfg_xaddr(PCI_BUS, PHYS_DEV,
						func, (reg + 4));
			NATIVE_WRITE_MAS_W(addr_port, xaddr, MAS_IOADDR);
			mask = 0;
			break;
		}
	}

	while (size & (reg & 0x3)) {
		rval |= (NATIVE_READ_MAS_B(data_port + mask,
						MAS_IOADDR) << (cnt * 8));
		if (!--size)
			break;
		++mask;
		++cnt;
	}

	switch (size) {
	case 0:
		break;
	case 1:
		rval = NATIVE_READ_MAS_B(data_port, MAS_IOADDR);
		break;
	case 2:
		rval = NATIVE_READ_MAS_H(data_port, MAS_IOADDR);
		break;
	case 4:
		rval = NATIVE_READ_MAS_W(data_port, MAS_IOADDR);
		break;
	default:
		break;
	}
	return rval;
}

#define SB_read_config8(reg, func)	\
		((char)SB_read_config(reg, func, sizeof(char)))
#define SB_read_config16(reg, func)	\
		((short)SB_read_config(reg, func, sizeof(short)))
#define SB_read_config32(reg, func)	\
		((int)SB_read_config(reg, func, sizeof(int)))

static inline void SB_write_config(int xdata, int reg, int func, int size)
{
	unsigned int xaddr;
	int mask = reg & 0x3;
	int data;
	int cnt = 0;
	xaddr = pci_cfg_xaddr(PCI_BUS, PHYS_DEV, func, reg);
	NATIVE_WRITE_MAS_W(addr_port, xaddr, MAS_IOADDR);
	while (mask) {
		data = xdata >> (8 * cnt);
		NATIVE_WRITE_MAS_B(data_port + mask, data, MAS_IOADDR);
		if (!--size)
			break;
		++mask;
		++cnt;
		if (mask == 4) {
			xaddr = pci_cfg_xaddr(PCI_BUS, PHYS_DEV,
						func, (reg + 4));
			NATIVE_WRITE_MAS_W(addr_port, xaddr, MAS_IOADDR);
			mask = 0;
			break;
		}
	}

	while (size & (reg & 0x3)) {
		data = xdata >> (8 * cnt);
		NATIVE_WRITE_MAS_B(data_port + mask, data, MAS_IOADDR);
		if (!--size)
			break;
		++mask;
		++cnt;
	}

	switch (size) {
	case 0:
		break;
	case 1:
		NATIVE_WRITE_MAS_B(data_port, xdata, MAS_IOADDR);
		break;
	case 2:
		NATIVE_WRITE_MAS_H(data_port, xdata, MAS_IOADDR);
		break;
	case 4:
		NATIVE_WRITE_MAS_W(data_port, xdata, MAS_IOADDR);
		break;
	default:
		break;
	}
}


#define SB_write_config8(xdata, reg, func)	\
		SB_write_config(xdata, reg, func, sizeof(char))
#define SB_write_config16(xdata, reg, func)	\
		SB_write_config(xdata, reg, func, sizeof(short))
#define SB_write_config32(xdata, reg, func)	\
		SB_write_config(xdata, reg, func, sizeof(int))

#endif /* _SOUTHBRIDGE_H_ */
