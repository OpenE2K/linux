
#include "pci.h"

typedef unsigned long pciaddr_t;
typedef u8 byte;
typedef u16 word;


struct pci_filter {
	int bus, slot, func;	/* -1 = ANY */
	int vendor, device;
};

#define PCITAG struct pci_filter *
#define pciVideoPtr struct bios_pci_dev *

extern int pciNumBuses;

int pciInit(void);
int pciExit(void);


PCITAG findPci(unsigned short bx);
u32 pciSlotBX(pciVideoPtr pvp);

void pciWriteLong(PCITAG tag, u32 idx, u32 data);
void pciWriteWord(PCITAG tag, u32 idx, u16 data);
void pciWriteByte(PCITAG tag, u32 idx, u8 data);

u32 pciReadLong(PCITAG tag, u32 idx);
u16 pciReadWord(PCITAG tag, u32 idx);
u8 pciReadByte(PCITAG tag, u32 idx);
