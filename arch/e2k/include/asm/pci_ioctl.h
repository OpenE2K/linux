/*
 * include/asm-e2k/pci_ioctl.h
 *
 *	The IOCTLs supported by the hb driver
 *	(the auxiliary driver of PCI host bridge
 *	 is implemented in the debugging and testing
 *	 purposes only; see arch/e2k/kernel/pci_hb_drv.c).
 *
 *	Copyright (C) 2002 MCST
 */

#ifndef	__E2K_PCI_IOCTL_H__
#define	__E2K_PCI_IOCTL_H__

/*
 * This illegal file is used in both user and kernel levels and
 * uses the common data representation specified in the pci_e2k.h file.
 * Since the file is illegal and pci_e2k.h should not be located in the
 * include directory I tolerate this direct path.
 */
#include "../../../../kernel/linux-2.4.0/arch/e2k/kernel/pci_e2k.h"


/*
 *
 * The e2k PCI host bridge ioctl structures
 *
 */

typedef struct pam_setup_t {
	int	pamreg_scale;
} pam_setup_t;

typedef struct int_location_t {
	e2k_addr_t	phys_address;
	int		value;
} int_location_t;

typedef union pci_ioctls_t {
	pam_setup_t	pam_setup;
	int		pamreg_default_state_flag;
	unsigned char	pam_buf[PCI_PAMREG_LEN];
	int_location_t	int_location;
} pci_ioctls_t;

/*
 * Key for pci_ioctl driver ioctls
 */
#define	PCI_IOC			('S' << 8)

/*
 * Ioctls supported by pci_ioctl driver
 */
#define	PAM_SETUP_IOCTL			(PCI_IOC | 1)
#define	PAM_READ_IOCTL			(PCI_IOC | 2)
#define	GET_PAM_DEFAULT_FLAG_IOCTL	(PCI_IOC | 3)
#define	WRITE_INT_LOCATION_IOCTL	(PCI_IOC | 4)
#define	READ_INT_LOCATION_IOCTL		(PCI_IOC | 5)

#define	TEST_0_IOCTL			(PCI_IOC | 6)

#endif  /* __E2K_PCI_IOCTL_H__ */
