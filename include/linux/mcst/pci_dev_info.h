/* 
 * Supported by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST
 *
 */

#include <linux/mcst/ddi.h>

struct pci_dev_info {
	char *prom_name;
	unsigned short vendor;
	unsigned short device;
	char *options;
	int  args[2];
};


#define PCI_VENDOR_ID_MCST	0x5453
#define PCI_DEVICE_ID_MCST_PDC	0x4350
#define PCI_DEVICE_ID_MCST_MPV	0x4360

#define MCST_DEVICE_DRIVERS	\
	{ "MCST,mvp", 	0, 0, "mvp-parity,mvp-polar,", {0, 0} },	\
	{ "MCST,mbkp1", 0, 0 },	\
	{ "MCST,mbkp2", 0, 0 },	\
	{ "MCST,pidc", 	PCI_VENDOR_ID_MCST, PCI_DEVICE_ID_MCST_PDC },	\
	{ "MCST,mpv", PCI_VENDOR_ID_MCST, PCI_DEVICE_ID_MCST_MPV },	\
	{ "MCST,FOO", 	0, 0 },	\
	{ "MCST,FOO", 	0, 0 },	

