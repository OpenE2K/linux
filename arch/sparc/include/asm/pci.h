#ifndef ___ASM_SPARC_PCI_H
#define ___ASM_SPARC_PCI_H
#if defined(__sparc__) && defined(__arch64__)
#ifdef CONFIG_E90S
#include <asm/pci_e90s.h>
#else
#include <asm/pci_64.h>
#endif
#else
#include <asm/pci_32.h>
#endif

#include <asm-generic/pci-dma-compat.h>

#endif
