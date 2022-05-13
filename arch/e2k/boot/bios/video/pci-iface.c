
#ifndef IN_MODULE
#include <stdio.h>
#include <pci/pci.h>
#endif

#include <x86emu.h>
#include "pci-iface.h"
#include "pci.h"

#define PCITAG struct pci_filter *

#define DEBUG_PCI 1

struct pci_access *pacc;
struct bios_pci_dev *dev;

struct pci_filter ltag;


int pciNumBuses = 0;

int pciInit(void)
{
	return 0;
}

int pciExit(void)
{

	return 0;
}

PCITAG findPci(unsigned short bx)
{
	PCITAG tag = &ltag;

	int bus = (bx >> 8) & 0xFF;
	int slot = (bx >> 3) & 0x1F;
	int func = bx & 0x7;

	tag->bus = bus;
	tag->slot = slot;
	tag->func = func;


	if (pci_find_slot(bus, PCI_DEVFN(slot, func)))
		return tag;

	return NULL;
}

u32 pciSlotBX(pciVideoPtr pvp)
{
	
	PCITAG tag = &ltag;

	tag->bus = pvp->bus->number;
	tag->slot = PCI_SLOT(pvp->devfn);
	tag->func = PCI_FUNC(pvp->devfn);

	return (tag->bus << 8) | (tag->slot << 3) | (tag->func);
}

u8 pciReadByte(PCITAG tag, u32 idx)
{
	struct bios_pci_dev *d;

	u8 res;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func)))) {
		bios_pci_read_config_byte(d, (u8) idx, &res);
		return res;
	}

#ifdef DEBUG_PCI
	printf("PCI: device not found while read byte (%x:%x.%x)\n",
	       tag->bus, tag->slot, tag->func);
#endif
	return 0;
}

u16 pciReadWord(PCITAG tag, u32 idx)
{
	struct bios_pci_dev *d;

	u16 res;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func)))) {
		bios_pci_read_config_word(d, (u8) idx, &res);
		return res;
	}
#ifdef DEBUG_PCI
	printf("PCI: device not found while read word (%x:%x.%x)\n",
	       tag->bus, tag->slot, tag->func);
#endif
	return 0;
}

u32 pciReadLong(PCITAG tag, u32 idx)
{
	struct bios_pci_dev *d;

	u32 res;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func)))) {
		bios_pci_read_config_dword(d, (u8) idx, &res);
		return res;
	}
#ifdef DEBUG_PCI
	printf("PCI: device not found while read long (%x:%x.%x)\n",
	       tag->bus, tag->slot, tag->func);
#endif
	return 0;
}


void pciWriteLong(PCITAG tag, u32 idx, u32 data)
{
	struct bios_pci_dev *d;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func))))
		bios_pci_write_config_dword(d, (u8) idx, data);
#ifdef DEBUG_PCI
	else
		printf("PCI: device not found while write long (%x:%x.%x)\n",
		       tag->bus, tag->slot, tag->func);
#endif
}

void pciWriteWord(PCITAG tag, u32 idx, u16 data)
{
	struct bios_pci_dev *d;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func))))
		bios_pci_write_config_word(d, (u8) idx, data);
#ifdef DEBUG_PCI
	else
		printf("PCI: device not found while write word (%x:%x.%x)\n",
		       tag->bus, tag->slot, tag->func);
#endif

}

void pciWriteByte(PCITAG tag, u32 idx, u8 data)
{
	struct bios_pci_dev *d;
	if ((d = pci_find_slot(tag->bus, PCI_DEVFN(tag->slot, tag->func))))
		bios_pci_write_config_byte(d, (u8) idx, data);
#ifdef DEBUG_PCI
	else
		printf("PCI: device not found while write long (%x:%x.%x)\n",
		       tag->bus, tag->slot, tag->func);
#endif
}
