/*
 * Copyright (c) 2001-2002, by ZAO MCST.
 * All Rights Reserved.
 * macctl.h
 */
#ifndef	__LINUX_MAC_MAC_KERNEL_H
#define	__LINUX_MAC_MAC_KERNEL_H

#ifdef __KERNEL__
#include <linux/mac/mac_types.h>
#ifdef CONFIG_MAC_

/*
 * Mandatory Access Control (MAC) enabled
 */

/* kernel notation for identifier of MAC subject */
typedef mac_subject_id_t kmac_subject_id_t;

/* kernel notation for identifier of MAC security label */
typedef mac_label_id_t kmac_label_id_t;

/* kernel notation for MAC access mode to an object */
typedef mac_mode_t kmac_mode_t;

/* kernel notation for identifier of MAC user */
typedef mac_user_id_t kmac_user_id_t;

/* kernel notation of network address for MAC network address object */
typedef mac_addr_t kmac_addr_t;

/* kernel notation of network port number for MAC network port object */
typedef mac_port_t kmac_port_t;

/* kernel notation of network protocol number for MAC network port object */
typedef mac_proto_t kmac_proto_t;

/*
 * Declaration of interface activation flag variable for MAC.
 * The variable is defined in uts/common/os/main.c file.
 * If the variable has zero value no kernel's interface function
 * for MAC must be called. This must be checked by all code before
 * any call to the functions.
 */
extern int mac_active;
extern int mac_attached;
extern unsigned int mac_test_inode;
/*
 * The pointer setup to a function for checking MAC rights for user-
 * owned object in kernel.
 */
extern int (*kmac_access_userp)(kmac_subject_id_t, kmac_user_id_t, int);

/*
 * The pointer setup to a function for checking MAC rights for network
 * address in kernel.
 */
extern int (*kmac_access_addrp)(kmac_subject_id_t, kmac_addr_t, int);

/*
 * The pointer setup to a function for checking MAC rights for network
 * port number in kernel.
 */
extern int (*kmac_access_portp)(kmac_subject_id_t, kmac_port_t,
    kmac_proto_t, int);

extern int (*sys_macctl_real)(register int request, register void *data, 
							register int size);
extern asmlinkage int sys_macctl(register int request, register void *data, 
							register int size);

#endif /* CONFIG_MAC_ */
#endif /* _KERNEL */
#endif /* __LINUX_MAC_MAC_KERNEL_H */

