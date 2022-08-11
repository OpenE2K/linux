#ifndef _UAPI_MCST_SELFTEST_H_
#define _UAPI_MCST_SELFTEST_H_

#define MCST_SELFTEST_MAGIC 0x7777 // needed other ???

#define BUS_SBUS	0x1
#define BUS_PCI		0x2
#define BUS_NONE	0x3

typedef struct selftest_pci {
	int vendor;
	int device;
	int class;
	int major;
	int minor;
	int bus;
	int slot;
	int func;
	char name[256];
} selftest_pci_t;


/*
 * description for selftest_sbus_t:
 *
 * bus:		Always zero
 * br_slot:	If there is a expander (MRSH device), the number of the slot
 *		in which it is, otherwise, -1
 * slot:	If there is a expander (MRSH device), the number of the slot
 *		in the expander, or simply the number of slots
 * address:	Start address of mmaping memory cells on sbus
 */
typedef struct selftest_sbus {
	int major;
	int minor;
	int bus;
	int br_slot;
	int slot;
	int address;
	char name[256];
} selftest_sbus_t;


/*
 * For devices not owned buses!
 */
typedef struct selftest_nonbus {
	int major;
	int minor;
	char name[256];
} selftest_nonbus_t;


union selftest_bus  {
	selftest_sbus_t		sbus;
	selftest_pci_t		pci;
	selftest_nonbus_t	nonbus;
};


typedef struct selftest {
	int	bus_type;
	int	error;
	union selftest_bus info;
} selftest_t;

#endif  /* !(_UAPI_MCST_SELFTEST_H_) */
